const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const adminSDK = require("firebase-admin");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const stripe = require("stripe")(process.env.STRIPE_SECRET);

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

// --------------------------------------------------------
//  FIREBASE ADMIN INIT
// --------------------------------------------------------
try {
  const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
    "utf8"
  );
  const serviceAccount = JSON.parse(decodedKey);

  adminSDK.initializeApp({
    credential: adminSDK.credential.cert(serviceAccount),
  });

  console.log("Firebase Admin Initialized");
} catch (error) {
  console.error("Firebase Init Failed:", error.message);
}

// --------------------------------------------------------
//  JWT FUNCTION FOR ADMINS
// --------------------------------------------------------
const createAdminToken = (email) => {
  return jwt.sign({ email, role: "admin" }, process.env.ADMIN_SECRET, {
    expiresIn: "7d",
  });
};

// --------------------------------------------------------
//  MONGO CONNECTION
// --------------------------------------------------------
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fkvjwgn.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: false,
    deprecationErrors: true,
  },
});

let servicesCollection;
let adminCollection;
let usersCollection;
let decoratorsCollection;
let reviewsCollection;
let bookingCollections;
let paymentCollections;

async function run() {
  try {
    // await client.connect();

    const db = client.db("Style_Deco_db");
    servicesCollection = db.collection("services");
    adminCollection = db.collection("admins");
    usersCollection = db.collection("users");
    decoratorsCollection = db.collection("decorators");
    reviewsCollection = db.collection("reviews");
    bookingCollections = db.collection("bookings");
    paymentCollections = db.collection("payment")

    console.log("MongoDB Connected Successfully");
  } catch (error) {
    console.error("MongoDB Error:", error);
  }
}

// run();

// --------------------------------------------------------
//  ADMIN VERIFY (NO FIREBASE)
// --------------------------------------------------------
const verifyAdmin = async (req, res, next) => {
  const token = req.headers["x-admin-token"];
  if (!token) return next(); // Maybe Firebase user

  try {
    const decoded = jwt.verify(token, process.env.ADMIN_SECRET);
    req.user = decoded; // { email, role: "admin" }
    return next();
  } catch (error) {
    return res.status(403).send({ message: "Invalid admin token" });
  }
};

// --------------------------------------------------------
//  FIREBASE VERIFY (Normal Users)
// --------------------------------------------------------
const verifyFirebaseJWT = async (req, res, next) => {
  if (req.user) return next();

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = await adminSDK.auth().verifyIdToken(token);
    req.user = { email: decoded.email, role: "user" };

    // Safely check DB only if collection exists
    if (usersCollection) {
      const dbUser = await usersCollection.findOne({ email: decoded.email });
      if (dbUser?.role) req.user.role = dbUser.role;
    }

    next();
  } catch (error) {
    console.error("Token verification failed:", error.code || error.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// --------------------------------------------------------
//  CREATE ADMIN (One-time)
// --------------------------------------------------------
app.post("/create-admin", async (req, res) => {
  const { email, password } = req.body;

  const exists = await adminCollection.findOne({ email });
  if (exists) return res.status(400).send({ message: "Admin exists" });

  const hashed = await bcrypt.hash(password, 10);

  await adminCollection.insertOne({
    email,
    password: hashed,
    createdAt: new Date(),
  });

  res.send({ message: "Admin created" });
});

// --------------------------------------------------------
//  ADMIN LOGIN
// --------------------------------------------------------
app.post("/admin-login", async (req, res) => {
  const { email, password } = req.body;

  const adminUser = await adminCollection.findOne({ email });
  if (!adminUser) return res.status(404).send({ message: "Admin not found" });

  const match = await bcrypt.compare(password, adminUser.password);
  if (!match) return res.status(401).send({ message: "Invalid password" });

  const token = createAdminToken(email);

  res.send({ email, role: "admin", token });
});






// ==================================

app.get("/admin/users", verifyAdmin, async (req, res) => {
  try {
    const { search = "" } = req.query;

    let filter = {};
    if (search) {
      filter.$or = [
        { email: { $regex: search, $options: "i" } },
        { displayName: { $regex: search, $options: "i" } },
      ];
    }

    const users = await usersCollection
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ users });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load users" });
  }
});

// ========================================================
// 2. MAKE USER → DECORATOR
// ========================================================
function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

app.patch(
  "/admin/users/:email/make-decorator",
  verifyAdmin,
  async (req, res) => {
    try {
      const { email } = req.params;
      const { specialties } = req.body;

      const user = await usersCollection.findOne({
        email: { $regex: `^${escapeRegex(email)}$`, $options: "i" },
      });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const updated = await usersCollection.updateOne(
        { email: { $regex: `^${escapeRegex(email)}$`, $options: "i" } },
        {
          $set: {
            role: "decorator",
            specialties,
            isActive: true,
            updatedAt: new Date(),
          },
        }
      );

      res.json({ message: "User promoted to decorator" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ========================================================
// 3. TOGGLE DECORATOR ACTIVE / INACTIVE
// ========================================================
app.patch(
  "/admin/users/:email/toggle-active",
  verifyAdmin,
  async (req, res) => {
    try {
      const { email } = req.params;

      const user = await usersCollection.findOne({ email, role: "decorator" });
      if (!user) {
        return res.status(404).json({ message: "Decorator not found" });
      }

      const newStatus = !user.isActive;

      await usersCollection.updateOne(
        { email },
        {
          $set: {
            isActive: newStatus,
            updatedAt: new Date(),
          },
        }
      );

      res.json({
        message: newStatus ? "Decorator activated" : "Decorator deactivated",
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ========================================================
// 4. GET ACTIVE DECORATORS ONLY (for future assignment dropdown)
// ========================================================
app.get("/admin/decorators", verifyAdmin, async (req, res) => {
  try {
    const decorators = await usersCollection
      .find({ role: "decorator", isActive: true })
      .project({
        email: 1,
        displayName: 1,
        photoURL: 1,
        specialties: 1,
        rating: 1,
      })
      .sort({ rating: -1 })
      .toArray();

    res.json(decorators);
  } catch (error) {
    res.status(500).json({ message: "Failed to load decorators" });
  }
});







// ================================

// --------------------------------------------------------
//  WHO AM I (ROLE DETECTOR)
// --------------------------------------------------------
// --------------------------------------------------------
// FINAL /me ROUTE – Detect Admin OR Firebase User OR Decorator
// --------------------------------------------------------
// In server.js → Replace /me route
app.get("/me", async (req, res) => {
  try {
    // 1. Admin via x-admin-token
    const adminToken = req.headers["x-admin-token"];
    if (adminToken) {
      try {
        const decoded = jwt.verify(adminToken, process.env.ADMIN_SECRET);
        return res.send({ role: "admin", email: decoded.email });
      } catch {}
    }

    // 2. Firebase user
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.send({ role: "guest" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = await adminSDK.auth().verifyIdToken(token);
    const email = decoded.email;

    // Look up in users collection
    const dbUser = await usersCollection.findOne({ email });
    if (dbUser) {
      return res.send({
        role: dbUser.role || "user",
        email: dbUser.email,
        displayName: dbUser.displayName,
        photoURL: dbUser.photoURL,
      });
    }

    // If not in DB yet → still return user (so dashboard works)
    return res.send({ role: "user", email });

  } catch (error) {
    console.log("ME error:", error.message);
    return res.send({ role: "guest" });
  }
});




// UPDATE DECORATOR SPECIALTIES (ADMIN)
app.patch(
  "/admin/decorators/:email",
  verifyAdmin,
  async (req, res) => {
    try {
      const { email } = req.params;
      const { specialties } = req.body;

      if (!specialties || !Array.isArray(specialties)) {
        return res.status(400).json({ message: "Invalid specialties" });
      }

      const result = await usersCollection.updateOne(
        { email, role: "decorator" },
        {
          $set: {
            specialties,
            updatedAt: new Date(),
          },
        }
      );

      if (!result.modifiedCount) {
        return res
          .status(404)
          .json({ message: "Decorator not found" });
      }

      res.json({ message: "Decorator updated successfully" });
    } catch (err) {
      console.error("Update decorator error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);




// DELETE DECORATOR (ADMIN) → Revert to normal user
// DELETE DECORATOR (ADMIN) → Remove user completely
app.delete("/admin/decorators/:email", verifyAdmin, async (req, res) => {
  try {
    const { email } = req.params;

    const result = await usersCollection.deleteOne({ email });

    if (!result.deletedCount) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to delete user" });
  }
});





// ================

// CHECK IF USER IS DECORATOR
app.get("/users/decorator/:email", async (req, res) => {
  try {
    const email = req.params.email;

    const user = await usersCollection.findOne({
      email: { $regex: `^${email}$`, $options: "i" }
    });

    if (!user) {
      return res.status(404).json({ decorator: false });
    }

    return res.json({ decorator: user.role === "decorator" });
  } catch (error) {
    console.error("Decorator check error:", error);
    res.status(500).json({ decorator: false });
  }
});



// ===============

// --------------------------------------------------------
//  GET SERVICES (ADMIN + USERS)
// --------------------------------------------------------
app.get("/services", async (req, res) => {
  try {
    const list = await servicesCollection.find().toArray();
    res.send(list);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch services" });
  }
});

// --------------------------------------------------------
//  ADD SERVICE (ADMIN ONLY)
// --------------------------------------------------------
app.post("/services", verifyAdmin, async (req, res) => {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).send({ message: "Only admin can add services" });
  }

  const service = req.body;
  service.createdAt = new Date();

  const result = await servicesCollection.insertOne(service);
  res.send(result);
});

app.get("/services/:id", async (req, res) => {
  try {
    const service = await servicesCollection.findOne({
      _id: new ObjectId(req.params.id),
    });

    if (!service) {
      return res.status(404).json({ message: "Service not found" });
    }

    res.json(service);
  } catch (error) {
    console.error("Service error:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// Add a review (Firebase verified user)
app.post("/services/:id/review", verifyFirebaseJWT, async (req, res) => {
  const { id } = req.params; // service id
  const { rating, comment } = req.body;

  if (!rating || !comment)
    return res.status(400).send({ message: "Rating and comment required" });

  const review = {
    serviceId: id,
    userEmail: req.user.email,
    rating,
    comment,
    createdAt: new Date(),
  };

  try {
    const result = await reviewsCollection.insertOne(review);
    res.send({ message: "Review submitted", reviewId: result.insertedId });
  } catch (error) {
    res.status(500).send({ message: "Failed to submit review" });
  }
});



// --------------------------------------------------------
// UPDATE SERVICE (ADMIN ONLY)
// --------------------------------------------------------
app.patch("/services/:id", verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const updateData = req.body;

    const updated = await servicesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (!updated.modifiedCount) {
      return res.status(404).send({ message: "Service not found or no changes" });
    }

    res.send({ message: "Service updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to update service" });
  }
});


// --------------------------------------------------------
// DELETE SERVICE (ADMIN ONLY)
// --------------------------------------------------------
app.delete("/services/:id", verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    const deleted = await servicesCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (!deleted.deletedCount) {
      return res.status(404).send({ message: "Service not found" });
    }

    res.send({ message: "Service deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to delete service" });
  }
});



// --------------------------------------------------------
//  ADMIN: GET ALL BOOKINGS
// --------------------------------------------------------
app.get("/admin/bookings", verifyAdmin, async (req, res) => {
  try {
    const list = await bookingCollections
      .find()
      .sort({ createdAt: -1 })
      .toArray();

    res.send(list);
  } catch (error) {
    console.error("Admin Booking Fetch Error:", error);
    res.status(500).send({ message: "Failed to fetch all bookings" });
  }
});


// DELETE booking (Admin only)
app.delete("/admin/bookings/:id", verifyAdmin, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const deleted = await bookingCollections.deleteOne({
      _id: new ObjectId(bookingId),
    });

    if (!deleted.deletedCount)
      return res.status(404).send({ message: "Booking not found" });

    res.send({ message: "Booking deleted successfully" });
  } catch (err) {
    console.error("Booking delete error:", err);
    res.status(500).send({ message: "Failed to delete booking" });
  }
});



// UPDATE booking (Admin only)
app.put("/admin/bookings/:id", verifyAdmin, async (req, res) => {
  try {
    const bookingId = req.params.id;
    const updateData = req.body; // e.g., { status: "paid" }

    const updated = await bookingCollections.updateOne(
      { _id: new ObjectId(bookingId) },
      { $set: updateData }
    );

    if (!updated.matchedCount)
      return res.status(404).send({ message: "Booking not found" });

    res.send({ message: "Booking updated successfully" });
  } catch (err) {
    console.error("Booking update error:", err);
    res.status(500).send({ message: "Failed to update booking" });
  }
});




// --------------------------------------------------------
// --------------------------------------------------------
//  ADD BOOKING (Firebase JWT Verified User)
// --------------------------------------------------------
app.post("/bookings", verifyFirebaseJWT, async (req, res) => {
  const userEmail = req.user.email;
  const { serviceId, serviceName, cost, bookedAt } = req.body;

  if (!serviceId || !serviceName || !cost || !bookedAt)
    return res.status(400).send({ message: "All booking fields are required" });

  const booking = {
    userEmail,
    serviceId,
    serviceName,
    cost,
    bookedAt: new Date(bookedAt),
    status: "pending",
    createdAt: new Date(),
  };

  try {
    const result = await bookingCollections.insertOne(booking);
    res.send({ message: "Booking successful", bookingId: result.insertedId });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Failed to create booking" });
  }
});

// --------------------------------------------------------
//  GET USER BOOKINGS (Firebase JWT Verified User)
// --------------------------------------------------------
app.get("/bookings", verifyFirebaseJWT, async (req, res) => {
  const userEmail = req.user.email;

  try {
    const list = await bookingCollections
      .find({ userEmail })
      .sort({ createdAt: -1 })
      .toArray();

    res.send(list);
  } catch (error) {
    console.error("Booking fetch error:", error);
    res.status(500).send({ message: "Failed to fetch bookings" });
  }
});

// payment

app.post("/create-checkout-session", async (req, res) => {
  const paymentInfo = req.body;
  const amount = parseInt(paymentInfo.cost) * 100;
  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price_data: {
          currency: "bdt",
          unit_amount: amount,
          product_data: { name: paymentInfo.serviceName },
        },
        quantity: 1,
      },
    ],
    customer_email: paymentInfo.senderEmail,
    mode: "payment",
    metadata: {
      bookId: paymentInfo.bookId,
      serviceName: paymentInfo.serviceName, // add serviceName
    },
    success_url: `${process.env.SITE_HOST}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.SITE_HOST}/dashboard/payment-cancelled`,
  });

  res.send({ url: session.url });
});

app.get("/stripe-session/:id", async (req, res) => {
  try {
    const sessionId = req.params.id;
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (!session) return res.status(404).send({ message: "Session not found" });

    // You can include metadata
    res.send({
      status: session.payment_status, // "paid" or "unpaid"
      bookId: session.metadata.bookId,
      senderEmail: session.customer_email,
      amount: session.amount_total / 100,
      serviceName: session.metadata.serviceName || "Service",
      transactionId: session.payment_intent,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Failed to fetch Stripe session" });
  }
});


app.get("/services/:id/reviews", async (req, res) => {
  const { id } = req.params;

  try {
    const reviews = await reviewsCollection
      .find({ serviceId: id })
      .sort({ createdAt: -1 }) // latest first
      .toArray();
    res.send(reviews);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch reviews" });
  }
});


// --------------------------------------------------------
//  SAVE PAYMENT (After success)
// --------------------------------------------------------
// --------------------------------------------------------
//  SAVE PAYMENT (After success) - FIXED
// --------------------------------------------------------
app.post("/payments", verifyFirebaseJWT, async (req, res) => {
  try {
    const { bookId, senderEmail, amount, serviceName, transactionId } = req.body;

    // Check if payment already exists for this booking
    const existingPayment = await paymentCollections.findOne({ bookId });
    if (existingPayment) {
      return res.status(400).send({ message: "Payment already recorded" });
    }

    const payment = {
      bookId,
      senderEmail,
      amount,
      serviceName,
      transactionId,
      status: "paid",
      paidAt: new Date(),
    };

    // store in DB
    const result = await paymentCollections.insertOne(payment);

    // update booking status
    await bookingCollections.updateOne(
      { _id: new ObjectId(bookId) },
      { $set: { status: "paid" } }
    );

    res.send({ message: "Payment saved", insertedId: result.insertedId });
  } catch (error) {
    console.error("Payment save error:", error);
    res.status(500).send({ message: "Failed to save payment" });
  }
});



// --------------------------------------------------------
//  GET PAYMENT HISTORY
// --------------------------------------------------------
app.get("/payments", verifyAdmin, verifyFirebaseJWT, async (req, res) => {
  try {
    if (!req.user) return res.status(401).send({ message: "Unauthorized" });

    let filter = {};

    // Admin sees all payments
    if (req.user.role !== "admin") {
      filter.senderEmail = req.user.email; // normal user sees only theirs
    }

    const payments = await paymentCollections
      .find(filter)
      .sort({ paidAt: -1 })
      .toArray();

    res.send(payments);
  } catch (error) {
    console.error("Failed to fetch payments:", error);
    res.status(500).send({ message: "Failed to fetch payments" });
  }
});


// GET PAYMENTS FOR DECORATOR'S ASSIGNED BOOKINGS
app.get("/decorator/payments", verifyFirebaseJWT, async (req, res) => {
  try {
    if (req.user.role !== "decorator") {
      return res.status(403).send({ message: "Only decorators can access this" });
    }

    const decoratorEmail = req.user.email;

    // Find all bookings assigned to this decorator
    const assignedBookings = await bookingCollections
      .find({ decoratorEmail, status: "paid" })
      .toArray();

    const bookingIds = assignedBookings.map(b => b._id);

    // Get payments linked to those booking IDs
    const payments = await paymentCollections
      .find({ bookId: { $in: bookingIds.map(id => id.toString()) } })
      .sort({ paidAt: -1 })
      .toArray();

    // Enhance payments with service name (already has it), or add booking date if needed
    res.send(payments);
  } catch (error) {
    console.error("Decorator payments fetch error:", error);
    res.status(500).send({ message: "Failed to fetch earnings" });
  }
});






// --------------------------------------------------------
//  CANCEL PAYMENT
// --------------------------------------------------------
app.patch("/payments/:id/cancel", verifyFirebaseJWT, async (req, res) => {
  try {
    const paymentId = req.params.id;

    const updated = await paymentCollections.updateOne(
      { _id: new ObjectId(paymentId), senderEmail: req.user.email },
      { $set: { status: "cancelled" } }
    );

    if (!updated.modifiedCount)
      return res.status(404).send({ message: "Payment not found" });

    res.send({ message: "Payment cancelled" });
  } catch (error) {
    res.status(500).send({ message: "Failed to cancel payment" });
  }
});


// Assign a user as decorator (Admin only)
// ASSIGN DECORATOR TO A BOOKING
// ASSIGN DECORATOR TO A BOOKING
app.post("/admin/assign-decorator", verifyAdmin, async (req, res) => {
  try {
    const { bookingId, email } = req.body;

    const booking = await bookingCollections.findOne({
      _id: new ObjectId(bookingId),
    });

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    // Assign decorator
    await bookingCollections.updateOne(
      { _id: new ObjectId(bookingId) },
      {
        $set: {
          decoratorEmail: email,
          decoratorAssigned: true,
          assignedAt: new Date()
        },
      }
    );

    res.json({ message: "Decorator assigned successfully" });
  } catch (error) {
    console.error("Assign Decorator Error:", error);
    res.status(500).json({ message: "Failed to assign decorator" });
  }
});




app.get("/decorator/projects", verifyFirebaseJWT, async (req, res) => {
  try {
    const email = req.user.email;

    // Find bookings assigned to this decorator
    const projects = await bookingCollections
      .find({ decoratorEmail: email })
      .sort({ assignedAt: -1 })
      .toArray();

    res.json(projects);
  } catch (err) {
    console.error("Decorator Projects Error:", err);
    res.status(500).json({ message: "Failed to load assigned projects" });
  }
});


// UPDATE PROJECT STATUS (Decorator only)
app.patch("/decorator/update-status/:id", verifyFirebaseJWT, async (req, res) => {
  try {
    const id = req.params.id;
    const { projectStatus } = req.body;

    const updated = await bookingCollections.updateOne(
      { _id: new ObjectId(id) },
      { $set: { projectStatus } }
    );

    res.json({ message: "Status updated" });
  } catch (err) {
    console.error("Status Update Error:", err);
    res.status(500).json({ message: "Failed to update status" });
  }
});


// DELETE ASSIGNED PROJECT (Decorator only)
// DELETE ASSIGNED PROJECT → Actually: Unassign decorator (SAFE)
// In your server.js file, update the DELETE route for /decorator/projects/:id as follows:
// DELETE ASSIGNED PROJECT
app.delete("/decorator/projects/:id", verifyFirebaseJWT, async (req, res) => {
  try {
    const id = req.params.id;

    // ensure valid ObjectId
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid project ID" });
    }

    const email = req.user.email;

    const result = await bookingCollections.updateOne(
      { _id: new ObjectId(id), decoratorEmail: email },
      {
        $unset: {
          decoratorEmail: "",
          decoratorAssigned: "",
          assignedAt: "",
          projectStatus: "",
        },
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({
        message: "Project not found or not assigned to you",
      });
    }

    res.json({ message: "Assignment removed successfully" });
  } catch (err) {
    console.error("DELETE decorator project error:", err);
    res.status(500).json({ message: "Server error" });
  }
});





// POST /api/register-user  ← MUST BE THIS PATH
// POST /api/register-user  → THIS FIXES YOUR EMPTY SPECIALTIES & STATUS
// POST /api/register-user
app.post("/api/register-user", verifyFirebaseJWT, async (req, res) => {
  try {
    const firebaseUser = req.user;
    const { displayName, photoURL } = req.body;

    // LIST OF BEAUTIFUL SPECIALTIES
    const allSpecialties = [
      "Wedding Planner",
      "Birthday Planner",
      "Corporate Event Planner",
      "Home Decoration Specialist",
      "Concert & Stage Designer",
      "Outdoor Event Expert",
      "Floral & Theme Designer",
      "Luxury Event Stylist",
    ];

    // RANDOMLY PICK 2–4 SPECIALTIES FOR NEW USER
    const randomSpecialties = allSpecialties
      .sort(() => 0.5 - Math.random())
      .slice(0, Math.floor(Math.random() * 3) + 2); // 2 to 4 items

    const userData = {
      uid: firebaseUser.uid,
      email: firebaseUser.email,
      displayName: displayName || firebaseUser.email.split("@")[0],
      photoURL: photoURL || "https://i.ibb.co/4pB1q7q/user.png",
      role: "user",
      isActive: true, // ← ACTIVE FROM START
      specialties: randomSpecialties, // ← RANDOM SPECIALTIES ADDED
      rating: (Math.random() * 1 + 4).toFixed(1), // 4.0 – 5.0
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // UPSERT: Create if new, update name/photo if already exists
    await usersCollection.updateOne(
      { email: firebaseUser.email },
      {
        $setOnInsert: {
          uid: userData.uid,
          role: "user",
          isActive: true,
          specialties: randomSpecialties,
          rating: userData.rating,
          createdAt: userData.createdAt,
        },
        $set: {
          displayName: userData.displayName,
          photoURL: userData.photoURL,
          updatedAt: new Date(),
        },
      },
      { upsert: true }
    );

    res.send({
      message: "User registered with specialties!",
      specialties: randomSpecialties,
    });
  } catch (err) {
    console.error("Register user error:", err);
    res.status(500).send({ message: "Failed to register user" });
  }
});


// --------------------------------------------------------
app.get("/", (req, res) => {
  res.send("Style Deco Server Running");
});

// START SERVER ONLY AFTER DATABASE IS CONNECTED
run()
  .then(() => {
    app.listen(port, () => {
      console.log(`Server running on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("Failed to connect to MongoDB", err);
  });
