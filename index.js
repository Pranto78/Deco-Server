const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const admin = require("firebase-admin");
const bcrypt = require("bcrypt");

const app = express();
const port = process.env.PORT || 3000;

// middleware
app.use(express.json());
app.use(cors());

// =======================
// Firebase Admin (Base64 Key)
// =======================
try {
  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf8");
  const serviceAccount = JSON.parse(decoded);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });

  console.log("Firebase Admin Initialized");
} catch (err) {
  console.error("❌ Firebase Admin Init Failed:", err.message);
}

// =======================
// Verify Firebase JWT
// =======================
const verifyJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ message: "Unauthorized!" });

  const token = authHeader.split(" ")[1];

  try {
    const decodedUser = await admin.auth().verifyIdToken(token);
    req.user = decodedUser;
    next();
  } catch (error) {
    return res.status(403).send({ message: "Forbidden!" });
  }
};

// =======================
// MONGO DB CONNECTION
// =======================
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fkvjwgn.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();

    const db = client.db("Style_Deco_db");
    const servicesCollection = db.collection("services");
    const adminCollection = db.collection("admins");


    // ------------------ CREATE ADMIN (One-time) ------------------
app.post("/create-admin", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).send({ message: "Email and password required" });

  try {
    const existingAdmin = await adminCollection.findOne({ email });
    if (existingAdmin) return res.status(400).send({ message: "Admin already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await adminCollection.insertOne({
      email,
      password: hashedPassword,
      createdAt: new Date(),
    });

    res.send({ message: "Admin created successfully", adminId: result.insertedId });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to create admin" });
  }
});



// ------------------ ADMIN LOGIN ------------------
app.post("/admin-login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).send({ message: "Email and password required" });

  const adminUser = await adminCollection.findOne({ email });

  if (!adminUser) {
    return res.status(404).send({ message: "Admin not found" });
  }

  const isMatch = await bcrypt.compare(password, adminUser.password);

  if (!isMatch) {
    return res.status(401).send({ message: "Invalid password" });
  }

  // Admin successfully logged in
  return res.send({
    email: adminUser.email,
    role: "admin",
  });
});





// =======================
// GET CURRENT LOGGED-IN USER
// =======================
app.get("/me", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send({ role: "none" });

    const token = authHeader.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(token);

    const email = decoded.email;

    const adminUser = await adminCollection.findOne({ email });
    if (adminUser) return res.send({ role: "admin", email });

    const user = await usersCollection.findOne({ email });
    if (user) return res.send({ role: "user", email });

    const decorator = await decoratorsCollection.findOne({ email });
    if (decorator) return res.send({ role: "decorator", email });

    res.send({ role: "none" });
  } catch (error) {
    console.error(error);
    res.status(401).send({ role: "none" });
  }
});





    // ROUTE
   app.get("/services", verifyJWT, async (req, res) => {
  try {
    const services = await servicesCollection.find().toArray();
    res.send(services);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch services" });
  }
});

// Add service (Protected - only logged in users)
app.post("/services", verifyJWT, async (req, res) => {
  try {
    const service = req.body;
    service.createdAt = new Date();

    const result = await servicesCollection.insertOne(service);
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to add service" });
  }
});

    console.log("Connected to MongoDB!");
  } catch (err) {
    console.error("MongoDB Connection Error:", err);
  }
}

run().catch(console.error);

// =======================
app.get("/", (req, res) => {
  res.send("Style Deco server running!");
});
// =======================

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
