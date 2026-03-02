💬 Fullstack Chat Application

A real-time fullstack chat application built with the MERN Stack and Socket.io, featuring authentication, live messaging, online user tracking, and image uploads.

🚀 Live Demo

🔗 Live App: https://fullstack-chat-application-1-pdq2.onrender.com

🛠 Tech Stack
Frontend

React (Vite)

Tailwind CSS

DaisyUI

Zustand (State Management)

Socket.io Client

Axios

Backend

Node.js

Express.js

MongoDB (Mongoose)

JWT Authentication

Socket.io

Cloudinary (Image Uploads)

Deployment

Render (Backend + Frontend)

MongoDB Atlas

✨ Features

🔐 User Authentication (Signup / Login / Logout)

🔑 JWT-based secure sessions (HTTP-only cookies)

💬 Real-time messaging with Socket.io

🟢 Online/Offline user indicators

📸 Image message support (Cloudinary integration)

⚡ Instant message updates without refresh

🎨 Responsive UI using Tailwind + DaisyUI

🗂 Clean project structure (Frontend & Backend separated)

📂 Project Structure
chat-app/
│
├── backend/
│   ├── src/
│   ├── routes/
│   ├── controllers/
│   ├── models/
│   ├── lib/
│   └── index.js
│
├── frontend/
│   ├── src/
│   ├── components/
│   ├── pages/
│   └── store/
│
└── README.md
⚙️ Environment Variables

Create a .env file inside backend/:

PORT=5001
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
CLIENT_URL=http://localhost:5173

For production, set these in your hosting dashboard.

🧑‍💻 Running Locally
1️⃣ Clone the repository
git clone https://github.com/yourusername/fullstack-chat-application.git
cd fullstack-chat-application
2️⃣ Install Backend Dependencies
cd backend
npm install
3️⃣ Install Frontend Dependencies
cd ../frontend
npm install
4️⃣ Run the App

Open two terminals:

Backend:

cd backend
npm run dev

Frontend:

cd frontend
npm run dev

Visit:

http://localhost:5173
🌐 Production Build

Frontend build:

cd frontend
npm run build

Backend will serve the frontend automatically when:

NODE_ENV=production
🧠 What I Learned

Implementing real-time communication with Socket.io

Managing global state using Zustand

Handling JWT authentication securely with cookies

Deploying fullstack apps on Render

Debugging complex frontend-backend integration issues

📌 Future Improvements

Message read receipts

Typing indicators

Group chat support

Push notifications

User profile customization

🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

📄 License

This project is open-source and available under the MIT License.
