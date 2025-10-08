- Slotify

![Slotify Logo](https://res.cloudinary.com/dbm1vxr2h/image/upload/v1759568506/SlotifyLogo1_f0slsz.png)**Slotify** is a full-stack application designed to manage time slots and bookings efficiently. It features a robust Django backend for handling APIs, authentication, and business logic, paired with a modern Angular 20 frontend for a seamless user experience. The application supports user and admin roles, JWT-based authentication, and data encryption using ciphers, with a SQLite database for storage. Both the frontend and backend are served together, making deployment straightforward.

## Table of Contents

- Features
- Technology Stack
- Prerequisites
- Installation
  - Local Setup
  - Docker Setup
- Running the Application
- Authentication
- API Documentation
- Roles and Permissions
- Contributing
- License
- Contact

## Features

- **User Management**: Create, update, and manage users with distinct roles (User and Admin).
- **Slot and Booking System**: Create, view, and manage time slots and bookings with conflict detection.
- **Dashboard**: Provides an overview of categories, slots, bookings, and user statistics.
- **Role-Based Access**: Admins have elevated permissions, while users can sign up and book slots.
- **JWT Authentication**: Secure API access with JSON Web Tokens.
- **Encrypted Navigation**: User IDs are encrypted in URLs for enhanced security.
- **Responsive Frontend**: Built with Angular 20 for a modern, user-friendly interface.
- **API Documentation**: Available via Swagger UI for easy exploration of endpoints.

## Technology Stack

- **Frontend**: Angular 20, Angular Material
- **Backend**: Python 3.12, Django, Django REST Framework (DRF)
- **Authentication**: JSON Web Tokens (JWT)
- **Encryption**: Ciphers for secure data handling
- **Database**: SQLite (dbsqlite3)
- **API Documentation**: Swagger UI (available at `http://localhost:8001/swagger/`)
- **Deployment**: Docker (optional)

## Prerequisites

Before setting up the application, ensure you have the following installed:

- **Python** 3.12 or higher
- **Node.js** 18.x or higher (for Angular CLI)
- **npm** 9.x or higher
- **Git** for cloning the repository
- **Docker** (optional, for containerized setup)
- A modern web browser (e.g., Chrome, Firefox)

## Installation

### Local Setup

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/SaiIndusVision/Slotify.git
   cd Slotify
   ```

2. **Set Up the Backend**:

   - Activate a virtual environment:

     ```bash
     source slotify_env/bin/activate  # On Windows: slotify_env\Scripts\activate
     ```

   - Install backend dependencies:

     ```bash
     pip install -r backend/requirements.txt
     ```

   - Run Local Server:

     ```bash
     cd backend
     python manage.py runserver 8001 ### Strict use since backend is running on 8001
     ```

3. **Set Up the Frontend**:

   - Navigate to the frontend directory:

     ```bash
     git clone https://github.com/SaiIndusVision/CTS-Frontend.git
     ```

   - Install frontend dependencies:

     ```bash
     npm install
     ```

    - Install frontend dependencies:

     ```bash
     ng serve ### for running server runs on 4200
     ```

   - The frontend is pre-built and served via the Django backend, so no separate build step is required unless modifying the frontend code.

4. **Environment Configuration**:

   - Create a `.env` file in the `backend` directory if required (e.g., for JWT secret keys or other configurations). Example:

     ```env
     SECRET_KEY=your-django-secret-key
     DEBUG=True
     ```
     ```environment.ts
     AES_KEY=AES_KEY
     ```

   - Ensure the SQLite database (`db.sqlite3`) is set up automatically during migrations.


### Docker Setup

1. **Pull the Docker Image**:

   ```bash
   docker pull saitr06/slotify:v1
   ```

2. **Run the Docker Container**:

   ```bash
   docker run -d -p 8001:8001 saitr06/slotify:v1
   ```

   - This maps port `8001` on your host to the container, making the application accessible at `http://localhost:8001`.

3. **Verify the Application**:

   - Open your browser and navigate to `http://localhost:8001` to confirm the application is running.
   - Access the API documentation at `http://localhost:8001/swagger/`.

## Running the Application

1. **Local Environment**:

   - From the `backend` directory, start the Django server:

     ```bash
     python manage.py runserver 0.0.0.0:8001
     ```

   - The application will be available at `http://localhost:8001`.

   - The frontend is served from the compiled build files integrated with the Django backend.

2. **Docker Environment**:

   - If using Docker, the application is already running after the `docker run` command.
   - Access the application at `http://localhost:8001`.

3. **Accessing the Application**:

   - Open `http://localhost:8001` in your browser to view the frontend.
   - Navigate to `http://localhost:8001/swagger/` for API documentation.

## Authentication

- **Admin Credentials**:

  - **Email**: `saithimmareddy06@gmail.com`
  - **Password**: `Saitr481309@`
  - Use these credentials to log in as an admin and access administrative features.

- **User Sign-Up**:

  - Users can sign up through the frontend interface to create their own accounts.
  - After signing up, users can log in and book slots based on their role.

- **JWT Authentication**:

  - The backend uses JSON Web Tokens for secure API access.
  - Obtain a JWT token via the `/api/refresh_token/` endpoint (see Swagger documentation).

## API Documentation

- All API endpoints are documented using Swagger UI.
- Access the documentation at: `http://localhost:8001/swagger/`.
- The Swagger interface provides details on endpoints for managing users, slots, bookings, categories, and the dashboard.

## Roles and Permissions

Slotify supports two roles:

- **Admin**:
  - Can manage users, slots, categories, and bookings.
  - Has access to the dashboard for system-wide statistics.
  - Example: Log in with the provided admin credentials.
- **User**:
  - Can sign up, log in, and book available slots.
  - Limited to viewing and managing their own bookings.
