# Ecommerce Website with JWT Authentication

## Description
This project is a fully responsive ecommerce website with user authentication implemented using Passport.js. It utilizes JWT (JSON Web Tokens) for secure authentication and authorization, supporting both local authentication and JWT-based authentication. 

![Ecommerce Website Screenshot](./dist/screenshot.png)

## Features

- **MERN Stack**: Utilizes MongoDB, Express.js, React.js, and Node.js for full-stack development.
- **Redux**: Implements Redux for state management in the frontend, enabling efficient data flow and global state management.
- **Passport.js Authentication**: Implements Passport.js strategies such as local authentication and JWT authentication for secure user authentication and authorization.
- **Stripe API Integration**: Utilizes the Stripe API for processing payments, ensuring secure and reliable payment transactions.
- **Webhooks**: Implements webhooks to receive real-time updates from Stripe, enhancing payment processing functionality.
- **Fully Responsive Design**: Offers a responsive user interface that adapts seamlessly to various screen sizes and devices.
- **Ecommerce Functionality**: Provides a comprehensive ecommerce platform with features such as product browsing, selection, cart management, admin functionality and secure checkout.

## Installation

### Prerequisites
- Node.js
- MongoDB

### Steps
1. Clone the repository.
2. Navigate to the project directory.
3. Install dependencies using `npm install`.
4. Create a `.env` file in the root directory of the project.
5. Configure environment variables as described in the [Environment Variables](#environment-variables) section.
6. Run the frontend and backend servers using `npm run dev`.

## Environment Variables
The project uses environment variables to configure various settings. Create a `.env` file
- **PORT**: The port number on which the server will listen for incoming connections.
- **MONGODB_URL**: Set the MongoDB connection URI.
- **DB_PASSWORD**: Password for connecting to the MongoDB database.
- **WEBHOOK_KEY**: Set the secret key used to authenticate webhook requests.
- **STRIPE_SECRET_KEY**: Set your Stripe API keys for processing payments.
- **SESSION_KEY**: Set a secret key for session creation and JWT token generation.
- **MAIL_PASSWORD**: Set this environment variable to your Gmail account password. It is used to send the forgot password email, specifically from the configured Gmail account.

## Usage

### Frontend
1. Access the frontend server using the provided URL.
2. Browse through the product catalog, add items to the cart, and proceed to checkout.
3. Complete the checkout process, providing necessary details for payment.
4. Receive real-time updates on payment status through webhooks.

### Backend
1. Access the backend server using the provided URL.
2. Utilize the implemented Passport.js strategies for user authentication and authorization.
3. Manage product data and orders stored in the MongoDB database.
4. Handle incoming payment requests and process payments using the Stripe API.

# Live URL
[Live Demo](https://supersyn.onrender.com)

## Technologies Used

- MongoDB
- Express.js
- React.js
- Node.js
- Redux
- Passport.js
- Stripe API

## Folder Structure

- `dist/`: Frontend code (React.js components, Redux store, actions, and reducers).
- `/`: Backend code (Express.js routes, controllers, and middleware).
- `models/`: MongoDB schema definitions.
- `utils/`: Utility functions and helpers.
- `config/`: Configuration files (environment variables, Passport.js settings, Stripe API keys).

## Credits

- Stripe API Documentation
- Passport.js Documentation
- React Documentation
- Node.js Documentation
- Express.js Documentation
- Mongoose Documentation

## Support

For support, questions, or feedback, please contact [harshparmar87990@gmail.com](mailto:harshparmar87990@gmail.com).
# wts-project
