# Slotify

![Slotify Logo](https://res.cloudinary.com/dbm1vxr2h/image/upload/v1759568506/SlotifyLogo1_f0slsz.png)

**Slotify** is a full-stack application designed to manage time slots and bookings efficiently. It features a robust Django backend for handling APIs, authentication, and business logic, paired with a modern Angular 20 frontend for a seamless user experience. The application supports user and admin roles, JWT-based authentication with a 1-minute access token lifetime, and data encryption using ciphers, with a SQLite database for storage.

## Table of Contents

- [Features](#features)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Local Setup](#local-setup)
  - [Docker Setup](#docker-setup)
- [Running the Application](#running-the-application)
- [Testing](#testing)
- [Authentication](#authentication)
- [API Documentation](#api-documentation)
- [Roles and Permissions](#roles-and-permissions)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

- **Slot and Booking System**: Create, view, and manage time slots and bookings with conflict detection.
- **Dashboard**: Provides an overview of categories, slots, bookings, and user statistics.
- **Role-Based Access**: Admins have elevated permissions, while users can sign up and book slots.
- **JWT Authentication**: Secure API access with JSON Web Tokens (1-minute access token lifetime, configurable).
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
- **Testing**: Pytest with parallel execution

## Prerequisites

Before setting up the application, ensure you have the following installed:

- **Python**: 3.10 or higher (3.12 recommended)
- **Node.js**: 18.x or higher (for Angular CLI)
- **npm**: 9.x or higher
- **Git**: For cloning the repositories
- **Docker**: Optional, for containerized setup
- **Pytest**: For running backend tests (included in `requirements.txt`)
- A modern web browser (e.g., Chrome, Firefox)

## Installation

### Local Setup

1. **Clone the Repositories**:

   - Backend:
     ```bash
     git clone https://github.com/SaiIndusVision/Slotify.git
     cd Slotify
     ```
   - Frontend:
     ```bash
     git clone https://github.com/SaiIndusVision/CTS-Frontend.git
     cd CTS-Frontend
     ```

2. **Set Up the Backend**:

   - Create and activate a virtual environment:
     ```bash
     python -m venv slotify_env
     source slotify_env/bin/activate  # On Windows: slotify_env\Scripts\activate
     ```

   - Install backend dependencies:
     ```bash
     pip install -r requirements.txt
     ```


3. **Set Up the Frontend**:

   - Navigate to the frontend directory:
     ```bash
     cd CTS-Frontend
     ```

   - Install frontend dependencies:
     ```bash
     npm install
     ```

   - Run the Angular development server (runs on port `4200` by default):
     ```bash
     ng serve
     ```

   - Note: The frontend can also be served via the Django backend using pre-built files on port `8001` (see [Running the Application](#running-the-application)).

4. **Environment Configuration**:

   - Create an `env.ext` file in the `backend` directory for environment configurations (e.g., JWT secret keys, AES key). Example:
     ```env
     SECRET_KEY=your-django-secret-key
     AES_KEY=your-shared-aes-key
     DEBUG=True
     ```

   - For the frontend, configure the AES key in `environment.ts`:
     ```typescript
     export const environment = {
       production: false,
       AES_KEY: 'your-shared-aes-key'
     };
     ```

   - Ensure the SQLite database (`db.sqlite3`) is set up automatically during migrations.

### Docker Setup

1. **Pull the Docker Image**:

   ```bash
   docker pull saitr06/slotify:v1
   ```

2. **Run the Docker Container**:

   ```bash
   docker run -d -p 8001:8001 -v $(pwd)/env.ext:/app/env.ext saitr06/slotify:v1
   ```

   - This maps port `8001` on your host to the container and mounts the `env.ext` file for configuration.

3. **Verify the Application**:

   - Open your browser and navigate to `http://localhost:8001` to confirm the application is running.
   - Access the API documentation at `http://localhost:8001/swagger/`.

## Running the Application

1. **Local Environment**:

   - From the directory, start the Django server:
     ```bash
     python manage.py runserver 8001
     ```

   - The application (including the pre-built frontend) will be available at `http://localhost:8001`.

   - If running the frontend separately (e.g., for development):
     ```bash
     cd CTS-Frontend
     ng serve
     ```
     The frontend will be available at `http://localhost:4200`, but ensure the backend is running on `http://localhost:8001` for API access.

2. **Docker Environment**:

   - The application runs automatically after the `docker run` command.
   - Access the application at `http://localhost:8001`.

3. **Accessing the Application**:

   - Open `http://localhost:8001` in your browser to view the integrated frontend and backend.
   - Navigate to `http://localhost:8001/swagger/` for API documentation.

## Testing

- Run backend test cases using pytest with parallel execution:
  ```bash
  pytest -v -n 8
  ```
  - The `-v` flag enables verbose output, and `-n 8` runs tests across 8 workers for faster execution.
  - Ensure `pytest-xdist` is installed (included in `requirements.txt`).

## Authentication

- **Admin Credentials**:
  - **Email**: `saithimmareddy06@gmail.com`
  - **Password**: `Saitr481309@`
  - Use these credentials to log in as an admin and access administrative features.

- **User Sign-Up**:
  - Users can sign up through the frontend interface to create their own accounts.
  - After signing up, users can log in and book slots based on their role.

- **JWT Authentication**:
  - The backend uses JSON Web Tokens (JWT) with a default access token lifetime of **1 minute**.
  - Obtain a JWT token via the `/api/refresh_token/` endpoint (see Swagger documentation).
  - To change the access token lifetime, modify the Django settings in `backend/settings.py`:
    ```python
    SIMPLE_JWT = {
        'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),  # Change to desired duration (e.g., 5 minutes)
        'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    }
    ```
  - After updating, restart the Django server to apply changes.

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


Thank you for using Slotify! We hope it streamlines your slot booking experience.