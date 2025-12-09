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
    await client.connect();

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

run();

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
  if (req.user) return next(); // Already admin

  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ message: "Unauthorized!" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = await adminSDK.auth().verifyIdToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).send({ message: "Invalid Firebase token" });
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

// --------------------------------------------------------
//  WHO AM I (ROLE DETECTOR)
// --------------------------------------------------------
app.get("/me", verifyAdmin, async (req, res) => {
  if (req.user?.role === "admin") {
    return res.send({ role: "admin", email: req.user.email });
  }

  // Check Firebase
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.send({ role: "guest" });

  try {
    const token = authHeader.split(" ")[1];
    const decoded = await adminSDK.auth().verifyIdToken(token);

    const email = decoded.email;

    if (await usersCollection.findOne({ email }))
      return res.send({ role: "user", email });

    if (await decoratorsCollection.findOne({ email }))
      return res.send({ role: "decorator", email });

    return res.send({ role: "guest" });
  } catch {
    return res.send({ role: "guest" });
  }
});

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

app.get("/services/:id", verifyFirebaseJWT, verifyAdmin, async (req, res) => {
  try {
    const service = await servicesCollection.findOne({
      _id: new ObjectId(req.params.id),
    });
    if (!service) return res.status(404).json({ message: "Service not found" });
    res.json(service);
  } catch (error) {
    console.error(error);
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
app.get("/payments", verifyFirebaseJWT, async (req, res) => {
  try {
    const email = req.user.email;

    const payments = await paymentCollections
      .find({ senderEmail: email })
      .sort({ paidAt: -1 })
      .toArray();

    res.send(payments);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch payments" });
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



// --------------------------------------------------------
app.get("/", (req, res) => {
  res.send("Style Deco Server Running");
});

// START SERVER ONLY AFTER DATABASE IS CONNECTED
run().then(() => {
  app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
});
