const mysql = require('mysql2');
require('dotenv').config(); // Load environment variables

// ✅ Create MySQL Connection
const connection = mysql.createConnection({
  host: 'localhost', // Change if using a remote database
  user: 'root', // Your MySQL username
  password: 'hamza', // Your MySQL password
  database: 'e_library_db' // Your database name
});

// ✅ Connect to MySQL
connection.connect(err => {
  if (err) {
    console.error('❌ Database connection failed:', err);
    return;
  }
  console.log('✅ MySQL Connected!');
});

module.exports = connection;