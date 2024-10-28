const express = require('express');
const axios = require('axios');
const multer = require('multer');
const Flutterwave = require('flutterwave-node-v3');
const open = import("open");
const http = require('http');
const { Server } = require('socket.io');
const app = express()
const server = http.createServer(app);
const cors = require('cors');
require('dotenv').config()
const jwt = require("jsonwebtoken")
const PORT = process.env.PORT || 5000;
const uuid = require('uuid');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { GridFsStorage } = require('multer-gridfs-storage');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');



const io = new Server(server, {
  cors: {
    origin: "*", // Enable CORS for all origins, or restrict it to your frontend URL.
  }
});

let loopCount = 0;
let musicStartTime = Date.now();
let musicDuration = 0; // This will be set by the client when it connects

// Function to calculate the elapsed time since music started
function getMusicProgress() {
  if (musicDuration === 0) return { loopCount: 0, timeInCurrentLoop: 0 }; // No music duration set yet
  const now = Date.now();
  const elapsedTime = now - musicStartTime;
  loopCount = Math.floor(elapsedTime / musicDuration);
  const timeInCurrentLoop = elapsedTime % musicDuration;
  return { loopCount, timeInCurrentLoop };
}

io.on('connection', (socket) => {
  console.log('A user connected');

  // Receive music duration from the client
  socket.on('setMusicDuration', (duration) => {
    musicDuration = duration;
    musicStartTime = Date.now();  // Reset the start time when the duration is set
    const currentProgress = getMusicProgress();
    socket.emit('musicStatus', currentProgress);
  });

  // Send current music status to a newly connected client
  socket.on('getMusicStatus', () => {
    const currentProgress = getMusicProgress();
    socket.emit('musicStatus', currentProgress);
  });

  socket.on('disconnect', () => {
    console.log('A user disconnected');
  });
});






//MongoDB Connection


const { MongoClient, ServerApiVersion, GridFSBucket, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.hree58n.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

let gfs;
let ffs;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    // Create a database and collections
    const database = client.db("bonds")
    const userCollections = database.collection("users");
    const ownedAssetCollections = database.collection("ownedAssets");
    const swapCollections = database.collection("swaps");

    gfs = new GridFSBucket(database, {
      bucketName: 'audioFiles'
    });

    ffs = new GridFSBucket(database, {
      bucketName: 'profilePhotos' 
    });

    //middleware 
    app.use(cors())
    app.use(bodyParser.json());
    app.use(express.json())
    app.use(express.urlencoded({ extended: true }));

    const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

    const storage = multer.memoryStorage(); // Store files in memory before uploading to GridFS
    const upload = multer({ storage });
    const { Readable } = require('stream');


    



    const verifyJWT = (req, res, next) => {
      const authHeader = req.headers['authorization'];

      if (!authHeader) {
        return res.status(401).json({ error: 'Authorization header missing' });
      }

      const token = authHeader && authHeader.split(' ')[1];

      console.log('Received token:', token); // Log token for debugging
      
      if (!token) return res.status(401).json({ message: 'Unauthorized access' });
    
      jwt.verify(token, process.env.ACCESS_SECRET, (err, user) => {
          if (err) return res.status(403).json({ message: 'Invalid token' });
          console.log('Decoded JWT:', user);
          req.user = user; // Store user data (including username) in req.user
          req.userId = user.userId; // Store the userId in the request
          next();
      });
    };


    // Verify the transaction and automatically transfer funds if successful
      app.post('/api/verify-and-transfer', async (req, res) => {
        const { reference, amount, recipient } = req.body;

        try {
          // Step 1: Verify the transaction
          const verificationResponse = await axios.get(
            `https://api.paystack.co/transaction/verify/${reference}`,
            {
              headers: {
                Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
              },
            }
          );

          const verificationData = verificationResponse.data.data;

          // Check if the payment was successful
          if (verificationData.status === 'success') {
            // Step 2: Create a transfer recipient using the recipient's bank details
            const recipientResponse = await axios.post(
              'https://api.paystack.co/transferrecipient',
              {
                type: 'nuban',
                name: recipient.name,
                account_number: recipient.account_number,
                bank_code: recipient.bank_code,
                currency: 'NGN',
              },
              {
                headers: {
                  Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
                  'Content-Type': 'application/json',
                },
              }
            );

            const recipientCode = recipientResponse.data.data.recipient_code;

            // Step 3: Initiate the transfer
            const transferResponse = await axios.post(
              'https://api.paystack.co/transfer',
              {
                source: 'balance',
                amount: 90 * 100, // Amount in kobo
                recipient: recipientCode,
                reason: 'Payment for services',
              },
              {
                headers: {
                  Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
                  'Content-Type': 'application/json',
                },
              }
            );

            return res.status(200).json({
              message: 'Transaction verified and transfer initiated successfully.',
              transfer: transferResponse.data,
            });
          } else {
            return res.status(400).json({
              message: 'Transaction verification failed.',
            });
          }
        } catch (error) {
          console.error('Error during transaction verification and transfer:', error);
          return res.status(500).json({ error: error.response?.data || error.message });
        }
      });


   

    

     app.post("/api/set-token", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_SECRET, {
        expiresIn: '24h'
      });
      res.send({token})
     })

     // Protected route
    app.get('/home', verifyJWT, (req, res) => {
      res.send(`Welcome to the homepage, ${req.user.username}`);
    });



    // Users route -- starts

    // Signup Route
    app.post('/signup', async (req, res) => {
      const { username, email, password } = req.body;

      // Check if username or email already exists
      const existingUser = await userCollections.findOne({
          $or: [{ username }, { email }],
      });

      if (existingUser) {
          return res.status(400).json({
              error: 'Username or Email already exists',
          });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Save user in MongoDB
      await userCollections.insertOne({
          username,
          email,
          password: hashedPassword,
      });

      res.status(201).json({ message: 'User registered successfully' });
    });


    // Endpoint to log in a user
    app.post('/login', async (req, res) => {
      const { username, password } = req.body;
  
      // Check if user exists
      const user = await userCollections.findOne({ username });
      if (!user) {
          return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // Compare hashed password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
          return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // Generate JWT token
      const token = jwt.sign({ username: user.username, userId: user._id, email: user.email }, process.env.ACCESS_SECRET, { expiresIn: '1h' });
      res.json({ token });
    });

 
    app.get('/users', async (req, res) => {
      const result = await userCollections.find().toArray();
      res.send(result);
    })

    app.get('/users/:username', verifyJWT, async (req, res) => {
      const username = req.params.username;
      const query = {username: username}
      const result = await userCollections.find(query).toArray();
      res.send(result);
    })

    app.get('/users/:username/myBonds', async (req, res) => {
      const username = req.params.username;
      const usersCollection = userCollections
      const user = await usersCollection.findOne({ username: username });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      const result= user.myBonds;
      res.send(result);
    })

    app.get('/users/:username/ongoingBonds', async (req, res) => {
      const username = req.params.username;
      const usersCollection = userCollections
      const user = await usersCollection.findOne({ username: username });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      const result= user.ongoingBonds;
      res.send(result);
    })



    app.patch('/addToAdoredList/:username', async (req, res) => {
      const signedInUser = req.params.username;
      const { targetUser } = req.body;
    
      try {
        // Find the signed-in user's document
        const userDoc = await userCollections.findOne({ username: signedInUser });
    
        // If user document doesn't exist, return an error
        if (!userDoc) return res.status(404).json({ error: 'User not found' });
    
        let adoredList = userDoc.adored || [];
        let updatedAdoredList;
    
        // Check if the target user is already in the adored list
        if (adoredList.includes(targetUser)) {
          // If already adored, remove them from the list
          updatedAdoredList = adoredList.filter((user) => user !== targetUser);
        } else {
          // If not adored, add them to the list
          adoredList.push(targetUser);
          updatedAdoredList = adoredList;
        }
    
        // Update the signed-in user's adored list
        await userCollections.updateOne(
          { username: signedInUser },
          { $set: { adored: updatedAdoredList } },
          {upsert: true}
        );
    
        res.json({ adored: updatedAdoredList });
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
      } 
    });


    app.get('/users/:username/adored/:targetUser', async (req, res) => {
      const signedInUser = req.params.username;
      const targetUser = req.params.targetUser;
    
      try {
        // Find the signed-in user's adored list
        const userDoc = await userCollections.findOne({ username: signedInUser });
    
        if (!userDoc) return res.status(404).json({ error: 'User not found' });
    
        // Check if the target user is adored
        const isAdored = userDoc.adored && userDoc.adored.includes(targetUser);
    
        res.json({ adored: isAdored });
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });



    // Endpoint to update the wallet address
    app.patch('/updateWalletAddress/:username', async (req, res) => {
      const { username } = req.params;
      const { walletAddress } = req.body;

      if (!walletAddress) {
        return res.status(400).json({ message: 'Wallet address is required' });
      }

      try {
        const result = await userCollections.updateOne(
          { username: username }, // Filter by username
          { $set: { walletAddress: walletAddress } }, // Update the walletAddress field
          {upsert: true}
        );

        if (result.modifiedCount > 0) {
          res.status(200).json({ message: 'Wallet address updated successfully' });
        } else {
          res.status(404).json({ message: 'User not found or no changes made' });
        }
      } catch (error) {
        res.status(500).json({ message: 'Internal server error', error: error.message });
      }
    });




    // User route -- ends

    // update user document... add to / delete from myBonds, onGoingBonds and dates 

    // Add to dates
    app.patch('/new-date/:username', verifyJWT, async (req, res) => {
      const username = req.params.username;
      const newDate = {...req.body, id:uuid.v4()};
      const options = {upsert: true};
      const updateDoc = {
          $push: {
             dates: newDate
          },
      }

      const result = await userCollections.findOneAndUpdate({username}, updateDoc, options)
      res.send(result)
    })


    // Add to ongoingBonds
    app.patch('/new-ongoingBonds/:username', verifyJWT, async (req, res) => {
      const username = req.params.username;
      const newOngongBond = {...req.body, id:uuid.v4()};
      const options = {upsert: true};
      const updateDoc = {
          $push: {
             ongoingBonds: newOngongBond
          },
      }

      const result = await userCollections.findOneAndUpdate({username}, updateDoc, options)
      res.send(result)
    })



    // Add to myBonds
    app.patch('/new-myBonds/:username', verifyJWT, async (req, res) => {
      const username = req.params.username;
      const newMyBond = {...req.body, id:uuid.v4()};
      const options = {upsert: true};
      const updateDoc = {
          $push: {
             myBonds: newMyBond
          },
      }

      const result = await userCollections.findOneAndUpdate({username}, updateDoc, options)
      res.send(result)
    })


    // remove from dates
    app.delete('/delete-date/:username/:id', verifyJWT, async (req, res) => {
      const { username, id } = req.params;
      const user = await userCollections.findOne({ username: username });
      if (!user) {
        return res.status(404).send('User not found');
      }
      const result = await userCollections.updateOne(
        { username: username },
        { $pull: { dates: { id: id } } }
      );
      if (result.modifiedCount === 0) {
        return res.status(404).send('Date entry not found or already deleted');
      }
      res.send(result);
    })

    // remove from myBond
    app.delete('/delete-myBond/:username/:id', verifyJWT, async (req, res) => {
      const {username, id} = req.params;
      const user = await userCollections.findOne({ username: username});
      if (!user) {
        return res.status(404).send('User not found');
      }

      const result = await userCollections.updateOne(
        { username: username},
        { $pull: { myBonds: { id: id} } }
      );
      if (result.modifiedCount === 0) {
        return res.status(404).send('Date entry not found or already deleted');
      }
      res.send(result);
    })

    // remove from ongoing Bonds
    app.delete('/delete-ongoingBonds/:username/:id', verifyJWT, async (req, res) => {
      const {username, id} = req.params;
      const user = await userCollections.findOne({ username: username});
      if (!user) {
        return res.status(404).send('User not found');
      }

      const result = await userCollections.updateOne(
        { username: username},
        { $pull: { ongoingBonds: { id: id} } }
      );
      if (result.modifiedCount === 0) {
        return res.status(404).send('Date entry not found or already deleted');
      }
      res.send(result);
    })

    // change status of OngoingBonds

    app.patch('/change-ongoingBondStatus/:username/:id', verifyJWT, async (req, res) => {
      const { username, id } = req.params;
      const { status } = req.body;

      if (typeof status !== 'string') {
        return res.status(400).send('Status must be a string');
      }

      const result = await userCollections.findOneAndUpdate(
        { username: username, 'ongoingBonds.id': id },
        {
          $set: { 'ongoingBonds.$.status': status }
        },
        { new: true, useFindAndModify: false } // Return the updated document
      );

      if (!result) {
        return res.status(404).send('User or bond not found');
      }
  
      res.send(result);
    })



    // update timeRemaining in Swaps

    app.patch('/updateTimeRemaining-InSwaps/:id', verifyJWT, async (req, res) => {
      const { id } = req.params;
      const { timeRemaining } = req.body;

      if (typeof timeRemaining !== 'string') {
        return res.status(400).send('timeRemaining must be a string');
      }

      const result = await swapCollections.updateOne(
        { _id: id },
        { $set: { timeRemaining: timeRemaining } }
      );

      if (result.matchedCount === 0) {
        return res.status(404).send('Document not found');
      }

      res.send({ modifiedCount: result.modifiedCount });
    })


    






    // OwnedAsset route -- starts
    // Endpoint to upload new owned asset
    app.post('/new-ownedAsset/:username', upload.fields([{ name: 'audioFile', maxCount: 1 }, { name: 'coverArt', maxCount: 1 }]), verifyJWT, async (req, res) => {
      try {
          const { username } = req.params;
          const { artistName, songName } = req.body;
          const audioFile = req.files['audioFile']?.[0];
          const coverArtFile = req.files['coverArt']?.[0];
          const userId = req.userId; // This should come from the decoded JWT
  
          if (!audioFile || !coverArtFile) {
              return res.status(400).json({ error: 'Audio file and cover art image are required.' });
          }
  
          if (!userId) {
              return res.status(404).json({ error: 'User not found.' });
          }
  
          console.log('Received userId:', userId);
          console.log('Received username:', username);
  
          // Upload cover art image to GridFS
          const coverArtUploadStream = gfs.openUploadStream(`${songName}_cover_${Date.now()}`, {
              contentType: coverArtFile.mimetype,
              metadata: {
                  uploaderId: userId,
                  artistName,
                  songName,
                  type: 'coverArt'
              }
          });
          const coverArtReadableStream = Readable.from(coverArtFile.buffer);
          coverArtReadableStream.pipe(coverArtUploadStream);
  
          coverArtUploadStream.on('error', (error) => {
              console.error('Error uploading cover art:', error);
              return res.status(500).json({ error: 'Failed to upload cover art.' });
          });
  
          coverArtUploadStream.on('finish', () => {
              const coverArtId = coverArtUploadStream.id;
  
              // Create an upload stream for the audio file
              const audioUploadStream = gfs.openUploadStream(`${songName}_${Date.now()}`, {
                  contentType: audioFile.mimetype,
                  metadata: {
                      uploaderId: userId,
                      artistName,
                      songName,
                      coverArtId, // Store the cover art file ID as metadata
                  }
              });
              const audioReadableStream = Readable.from(audioFile.buffer);
              audioReadableStream.pipe(audioUploadStream);
  
              audioUploadStream.on('error', (error) => {
                  console.error('Error uploading audio file:', error);
                  return res.status(500).json({ error: 'Failed to upload audio file.' });
              });
  
              audioUploadStream.on('finish', async () => {
                  const audioFileId = audioUploadStream.id;
  
                  // Save metadata to MongoDB
                  const songMetadata = {
                      userId,
                      username,
                      songName,
                      artistName,
                      audioFileId,
                      coverArtId,
                      uploadedAt: new Date()
                  };
  
                  try {
                      await ownedAssetCollections.insertOne(songMetadata);
                      res.status(201).json({
                          message: 'Audio file and cover art uploaded successfully',
                          audioFileId,
                          coverArtId
                      });
                  } catch (error) {
                      console.error('Error saving song metadata:', error);
                      res.status(500).json({ error: 'Failed to save song metadata.' });
                  }
              });
          });
  
      } catch (error) {
          console.error('Upload error:', error);
          res.status(500).json({ error: 'An error occurred while uploading the files.' });
      }
    });

    app.get('/ownedAssets', async (req, res) => {
      const result = await ownedAssetCollections.find().toArray();
      res.send(result);
    })
    // OwnedAsset route -- ends


    // Get Owned Asset by userId
    app.get('/ownedAssets/:userId', verifyJWT, async (req, res) => {
      try {
          const userId = req.params.userId;
          const songs = await ownedAssetCollections.find({ userId }).toArray();
  
          res.status(200).json(songs);
      } catch (error) {
          console.error('Error fetching songs:', error);
          res.status(500).json({ error: 'Failed to fetch songs' });
      }
    });


    app.get('/ownedAssetCoverArt/:coverArtId', async (req, res) => {
      const { coverArtId } = req.params;

      // Validate if the provided ID is a valid MongoDB ObjectId
      if (!ObjectId.isValid(coverArtId)) {
        return res.status(400).send('Invalid ID format.');
      }


      try {
        const downloadStream = gfs.openDownloadStream(new ObjectId(coverArtId));

        downloadStream.on('error', () => {
            res.status(404).send('No file exists with that ID!');
        });

        downloadStream.pipe(res);
      } catch (error) {
          console.error('Error fetching cover art:', error);
          res.status(500).send('Error retrieving cover art');
      }
    });


    // Upload profile photo
    app.post('/upload-profile-photo/:userId', upload.single('profilePhoto'), verifyJWT, async (req, res) => {
      try {
          const { userId } = req.params;
          const profilePhotoFile = req.file;

          if (!profilePhotoFile) {
              return res.status(400).json({ error: 'Profile photo is required.' });
          }

          // Find the user's existing profile photo
          const existingPhoto = await database.collection('profilePhotos.files').findOne({ 'metadata.userId': userId });

          // If an existing photo is found, delete it from GridFS
          if (existingPhoto) {
              await ffs.delete(new ObjectId(existingPhoto._id));
          }

          // Create a new upload stream for the profile photo
          const uploadStream = ffs.openUploadStream(`${userId}_profile_photo_${Date.now()}`, {
              contentType: profilePhotoFile.mimetype,
              metadata: { userId }
          });
          const readableStream = require('stream').Readable.from(profilePhotoFile.buffer);
          readableStream.pipe(uploadStream);

          uploadStream.on('error', (error) => {
              console.error('Error uploading profile photo:', error);
              res.status(500).json({ error: 'Failed to upload profile photo.' });
          });

          uploadStream.on('finish', () => {
              res.status(201).json({
                  message: 'Profile photo uploaded successfully',
                  profilePhotoId: uploadStream.id,
              });
          });
      } catch (error) {
          console.error('Upload error:', error);
          res.status(500).json({ error: 'An error occurred while uploading the profile photo.' });
      }
    });


    // Get profile photo
    app.get('/profile-photo/:userId', async (req, res) => {
      try {
          const { userId } = req.params;

          const cursor = ffs.find({ 'metadata.userId': userId }).sort({ uploadDate: -1 }).limit(1);
          const file = await cursor.next();

          if (!file) {
              return res.status(404).json({ error: 'Profile photo not found.' });
          }

          const downloadStream = ffs.openDownloadStream(file._id);
          res.set('Content-Type', file.contentType);
          downloadStream.pipe(res);
      } catch (error) {
          console.error('Error fetching profile photo:', error);
          res.status(500).json({ error: 'An error occurred while fetching the profile photo.' });
      }
    });






    // Swap route -- starts
    app.post('/new-swap', verifyJWT, async (req, res) => {
      const newSwap = req.body;
      const result = await swapCollections.insertOne(newSwap)
      res.send(result);
    })

    app.get('/swaps', async (req, res) => {
      const result = await swapCollections.find().toArray();
      res.send(result);
    })
    // Swap route -- ends











    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    
  }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('Welcome to Bonds server')
})

server.listen (PORT, () => {
    console.log(`Bonds platform app listening on port ${PORT}`)
})