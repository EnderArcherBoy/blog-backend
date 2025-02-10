# Blog Backend API

A Next.js-based backend API for a blog system with user roles and authentication.

## Features

- User authentication using JWT tokens
- Role-based authorization (admin, writer, reader)
- User management (CRUD operations)
- Protected API endpoints
- MySQL database with Prisma ORM

## Prerequisites

- Node.js 18 or higher
- MySQL database
- npm or yarn package manager

## Environment Setup

Create a `.env` file in the root directory with the following variables:

```properties
DATABASE_URL="mysql://root:@localhost:3306/blog"
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=your_clerk_publishable_key
CLERK_SECRET_KEY=your_clerk_secret_key
JWT_SECRET=your_jwt_secret
```

## Installation

```bash
# Install dependencies
npm install

# Set up the database
npx prisma migrate dev
```

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/logout` - User logout

### Users (Admin only)
- `GET /api/users` - Get all users
- `PATCH /api/users/:id` - Update user role
- `DELETE /api/users/:id` - Delete user

### Articles
- `GET /api/articles` - Get all articles
- `POST /api/articles` - Create article (writer/admin)
- `PATCH /api/articles/:id` - Update article (owner/admin)
- `DELETE /api/articles/:id` - Delete article (owner/admin)

## Authentication

All protected endpoints require a Bearer token in the Authorization header:

```bash
Authorization: Bearer your_jwt_token
```

## User Roles

- **Admin**: Full access to all endpoints
- **Writer**: Can create and manage their own articles
- **Reader**: Can read articles and comment

## Development

```bash
# Start development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## Error Handling

The API returns standard HTTP status codes:

- 200: Success
- 201: Created
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 500: Server Error

## Response Format

Success response:
```json
{
  "success": true,
  "message": "Operation successful",
  "data": {}
}
```

Error response:
```json
{
  "error": "Error message",
  "details": "Optional error details"
}
```

## License

MIT License - feel free to use this project for your own purposes.
