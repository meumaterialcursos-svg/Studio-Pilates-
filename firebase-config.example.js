// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyDLSAYuUU3O1DBXXOwP0Pt4rXEmGX6rsQ0",
  authDomain: "louise-891b3.firebaseapp.com",
  projectId: "louise-891b3",
  storageBucket: "louise-891b3.firebasestorage.app",
  messagingSenderId: "650364668322",
  appId: "1:650364668322:web:7cdd30f7a7ddb3d7c6cafb",
  measurementId: "G-JRLYKP7FZE"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
