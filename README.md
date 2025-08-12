# Mini Social - Local Demo

## Quick start

1. Install dependencies:
```
npm install
```

2. Initialize the database:
```
node migrate.js
```

3. Start the server:
```
node server.js
```

4. Open the app in your browser:
```
http://localhost:4000
```

## Notes
- Uploads are stored in `/uploads`.
- Database file: `/data/db.sqlite`.
- Edit `.env` to set `JWT_SECRET` and `PORT`.
