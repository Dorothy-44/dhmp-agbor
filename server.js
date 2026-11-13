// 1. Import our installed tools
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const session = require('express-session');
const multer = require('multer');
const path = require('path');


// Configure Image Storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images/'); // Saves to your existing images folder
    },
    filename: (req, file, cb) => {
        // Renames file to "user-5-1689234.jpg" to prevent overwriting
        cb(null, 'user-' + req.session.userId + '-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });


// 2. Initialize the Express app
const app = express();

// 3. Set up middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// 4. --- TURN ON SESSIONS (The Digital ID Badge) ---
app.use(session({
    secret: process.env.SESSION_SECRET || 'dhmp-agbor-secure-key-2026',
    resave: false,
    saveUninitialized: false
}));

// 5. --- DATABASE CONNECTION (Supabase / PostgreSQL) ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.query('SELECT 1')
    .then(() => console.log('Secure link established: Connected to PostgreSQL.'))
    .catch((err) => console.error('Database connection failed: ', err.message));


// 6. --- STATIC PAGE ROUTES ---
app.get('/', (req, res) => { res.render('index'); });
app.get('/about', (req, res) => { res.render('about'); });

app.get('/alert', (req, res) => { res.render('alert'); });
app.get('/confirm', (req, res) => { res.redirect('/booking'); });

app.get('/forgot-password', (req, res) => { res.render('forgot-password'); });
app.get('/login', (req, res) => { res.render('login'); });
app.get('/signup', (req, res) => { res.render('signup'); });
app.get('/booking-success', (req, res) => { res.render('booking-success'); });


// 7. --- AUTHENTICATION & SECURE ROUTES ---

// Patient Registration
app.post('/api/register', async (req, res) => {
    const { fullName, email, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.send("Passwords do not match.");
    }

    try {
        await pool.query(
            `INSERT INTO users (full_name, email, password, role) VALUES ($1, $2, $3, 'patient')`,
            [fullName, email, password]
        );
        res.redirect('/login');
    } catch (err) {
        if (err.code === '23505') return res.send("An account with this email already exists.");
        console.error("REGISTER ERROR:", err.message);
        res.status(500).send("An error occurred.");
    }
});


// Patient Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query(
            `SELECT * FROM users WHERE email = $1 AND password = $2`,
            [email, password]
        );

        if (result.rows.length > 0) {
            req.session.userId = result.rows[0].id;
            res.redirect('/dashboard');
        } else {
            res.send("Invalid email or password.");
        }
    } catch (err) {
        console.error("LOGIN ERROR:", err.message);
        res.status(500).send("Database error.");
    }
});


// Password Reset Logic (Direct Reset)
app.post('/api/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        // 1. Check if the email actually exists in the database
        const result = await pool.query(`SELECT id FROM users WHERE email = $1`, [email]);

        // 2. If the email isn't in the database, reject the reset
        if (result.rows.length === 0) {
            return res.send("We could not find an account registered with that email address.");
        }

        // 3. If the email exists, overwrite the old password with the new one
        await pool.query(`UPDATE users SET password = $1 WHERE email = $2`, [newPassword, email]);

        // 4. Success: send them back to the login page
        res.redirect('/login');
    } catch (err) {
        console.error("RESET ERROR:", err.message);
        res.status(500).send("Database error.");
    }
});


// Secure Dashboard
app.get('/dashboard', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    try {
        const userResult = await pool.query(
            `SELECT full_name, profile_pic FROM users WHERE id = $1`,
            [userId]
        );
        if (userResult.rows.length === 0) return res.redirect('/login');

        const patientName = userResult.rows[0].full_name;
        const profilePic = userResult.rows[0].profile_pic;

        // FETCH ALL UPCOMING APPOINTMENTS (Pending or Approved) closest date first
        let upcomingAppointments = [];
        try {
            const aptResult = await pool.query(
                `SELECT * FROM appointments WHERE patient_id = $1 AND status IN ('Pending', 'Approved') ORDER BY appointment_date ASC`,
                [userId]
            );

            upcomingAppointments = aptResult.rows.map(apt => ({
                status: apt.status,
                date: new Date(apt.appointment_date).toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }),
                timeSlot: apt.appointment_time,
                department: apt.department,
                facilityName: apt.facility || "Central Hospital"
            }));
        } catch (aptErr) {
            console.error("DASHBOARD APPOINTMENTS ERROR:", aptErr.message);
        }

        res.render('dashboard', {
            patientName: patientName,
            profilePic: profilePic,
            upcomingAppointments: upcomingAppointments
        });
    } catch (err) {
        console.error("DASHBOARD ERROR:", err.message);
        res.redirect('/login');
    }
});


// Secure Edit Profile View (Gets the data)
app.get('/edit-profile', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    try {
        const result = await pool.query(`SELECT * FROM users WHERE id = $1`, [userId]);
        if (result.rows.length === 0) return res.redirect('/login');

        res.render('edit-profile', { user: result.rows[0] });
    } catch (err) {
        console.error("EDIT PROFILE VIEW ERROR:", err.message);
        res.redirect('/login');
    }
});


// Secure Account Hub View
app.get('/account', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    try {
        const result = await pool.query(`SELECT * FROM users WHERE id = $1`, [userId]);
        if (result.rows.length === 0) return res.redirect('/login');

        res.render('account', { user: result.rows[0] });
    } catch (err) {
        console.error("ACCOUNT VIEW ERROR:", err.message);
        res.redirect('/login');
    }
});


// Secure Settings View
app.get('/settings', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    try {
        const result = await pool.query(`SELECT profile_pic FROM users WHERE id = $1`, [userId]);
        if (result.rows.length === 0) return res.redirect('/login');

        res.render('settings', { user: result.rows[0] });
    } catch (err) {
        console.error("SETTINGS VIEW ERROR:", err.message);
        res.redirect('/login');
    }
});


// Change Password Logic
app.post('/api/change-password', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    const { currentPassword, newPassword, confirmPassword } = req.body;

    // 1. Check if the new passwords match
    if (newPassword !== confirmPassword) {
        return res.send("New passwords do not match. Please go back and try again.");
    }

    try {
        // 2. Verify their current password in the database first
        const result = await pool.query(`SELECT password FROM users WHERE id = $1`, [userId]);
        if (result.rows.length === 0) return res.status(500).send("Database error.");

        if (currentPassword !== result.rows[0].password) {
            return res.send("Incorrect current password. Please go back and try again.");
        }

        // 3. If everything matches, update to the new password
        await pool.query(`UPDATE users SET password = $1 WHERE id = $2`, [newPassword, userId]);

        res.redirect('/settings');
    } catch (err) {
        console.error("CHANGE PASSWORD ERROR:", err.message);
        res.status(500).send("Failed to update password.");
    }
});


// Secure Deactivate View
app.get('/deactivate', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    try {
        const result = await pool.query(`SELECT profile_pic FROM users WHERE id = $1`, [userId]);
        if (result.rows.length === 0) return res.redirect('/login');

        res.render('deactivate', { user: result.rows[0] });
    } catch (err) {
        console.error("DEACTIVATE VIEW ERROR:", err.message);
        res.redirect('/login');
    }
});


// Deactivate Account Logic
app.post('/api/deactivate', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    const { password } = req.body;

    try {
        // 1. Verify their password first
        const result = await pool.query(`SELECT password FROM users WHERE id = $1`, [userId]);
        if (result.rows.length === 0) return res.status(500).send("Database error.");

        if (password !== result.rows[0].password) {
            return res.send("Incorrect password. Account deletion aborted.");
        }

        // 2. Clear all appointments to prevent foreign key errors
        await pool.query(`DELETE FROM appointments WHERE patient_id = $1`, [userId]);

        // 3. Delete the patient profile completely
        await pool.query(`DELETE FROM users WHERE id = $1`, [userId]);

        // 4. Destroy the session and send them to the homepage
        req.session.destroy(() => {
            res.redirect('/');
        });
    } catch (err) {
        console.error("DEACTIVATE ERROR:", err.message);
        res.status(500).send("Failed to delete account.");
    }
});


// Update Profile Logic (handles images)
app.post('/api/update-profile', upload.single('profileImage'), async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    const { fullName, email, phone, dob, address, emName, emPhone, existingProfilePic } = req.body;

    // If a new file was uploaded use its path, otherwise keep the old one
    const profilePicPath = req.file ? '/images/' + req.file.filename : existingProfilePic;

    const sql = `UPDATE users SET full_name = $1, email = $2, phone = $3, dob = $4, address = $5, em_name = $6, em_phone = $7, profile_pic = $8 WHERE id = $9`;

    try {
        // PostgreSQL rejects an empty string for a DATE column, so send NULL instead
        await pool.query(sql, [fullName, email, phone, dob || null, address, emName, emPhone, profilePicPath, userId]);
        res.redirect('/account');
    } catch (err) {
        console.error("UPDATE PROFILE ERROR:", err.message);
        res.status(500).send("Database error.");
    }
});


// Secure Patient History
app.get('/history', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    try {
        // 1. Fetch the user's profile picture first
        const userResult = await pool.query(`SELECT profile_pic FROM users WHERE id = $1`, [userId]);
        if (userResult.rows.length === 0) return res.redirect('/login');

        const profilePic = userResult.rows[0].profile_pic;

        // 2. Fetch all their appointments
        try {
            const result = await pool.query(
                `SELECT * FROM appointments WHERE patient_id = $1 ORDER BY appointment_date DESC`,
                [userId]
            );
            res.render('history', { historyData: result.rows, profilePic: profilePic });
        } catch (histErr) {
            console.error("HISTORY ERROR:", histErr.message);
            res.render('history', { historyData: [], profilePic: profilePic });
        }
    } catch (err) {
        console.error("HISTORY USER ERROR:", err.message);
        res.redirect('/login');
    }
});


// Secure Booking Page View
app.get('/booking', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    try {
        const result = await pool.query(`SELECT profile_pic FROM users WHERE id = $1`, [userId]);
        if (result.rows.length === 0) return res.redirect('/login');

        res.render('booking', { profilePic: result.rows[0].profile_pic });
    } catch (err) {
        console.error("BOOKING VIEW ERROR:", err.message);
        res.redirect('/login');
    }
});


// The Booking Review Page
app.post('/confirm', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    // 1. Grab everything they just typed into the booking form
    const { facility, department, appointmentDate, shift, reason } = req.body;

    try {
        // 2. Fetch their official name from the database
        const result = await pool.query(`SELECT full_name FROM users WHERE id = $1`, [userId]);
        if (result.rows.length === 0) return res.redirect('/login');

        const patientName = result.rows[0].full_name;

        // 3. Send the data to the confirm.ejs page to be displayed
        res.render('confirm', {
            patientName, facility, department, appointmentDate, shift, reason
        });
    } catch (err) {
        console.error("CONFIRM ERROR:", err.message);
        res.redirect('/login');
    }
});


// Appointment Booking Logic
app.post('/api/book-appointment', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    const { facility, department, appointmentDate, shift, reason } = req.body;

    const sql = `INSERT INTO appointments (patient_id, facility, department, appointment_date, appointment_time, reason, status) VALUES ($1, $2, $3, $4, $5, $6, 'Pending')`;

    try {
        await pool.query(sql, [userId, facility, department, appointmentDate || null, shift, reason]);
        res.redirect('/booking-success');
    } catch (err) {
        console.error("BOOKING SQL ERROR:", err.message);
        res.status(500).send("Database error.");
    }
});


// Patient Logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});


// ==========================================
// 8. --- ADMIN & STAFF ROUTES ---
// ==========================================

// Serve the Admin Login Page
app.get('/admin-login', (req, res) => {
    res.render('admin-login');
});

// Process Admin Login
app.post('/api/admin-login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // 1. Check the dedicated 'admins' table
        const result = await pool.query(
            `SELECT * FROM admins WHERE username = $1 AND password = $2`,
            [username, password]
        );

        if (result.rows.length > 0) {
            // 2. Create the multi-tenant admin session
            const admin = result.rows[0];
            req.session.adminId = admin.id;
            req.session.adminRole = admin.role;
            req.session.adminFacility = admin.facility;

            console.log(`STAFF LOGIN: ${admin.username} logged into ${admin.facility}`);
            res.redirect('/admin-dashboard');
        } else {
            // 3. Failed login
            res.send("Invalid staff credentials. Access Denied.");
        }
    } catch (err) {
        console.error("ADMIN LOGIN ERROR:", err.message);
        res.status(500).send("Database error.");
    }
});


// Secure Admin Dashboard
app.get('/admin-dashboard', async (req, res) => {
    const adminId = req.session.adminId;
    if (!adminId) return res.redirect('/admin-login');

    const facility = req.session.adminFacility;

    let sql = `
        SELECT appointments.*, users.full_name
        FROM appointments
        JOIN users ON appointments.patient_id = users.id
    `;
    const queryParams = [];

    // Filter by facility (unless it's the Master Admin)
    if (facility !== 'All Facilities') {
        sql += ` WHERE appointments.facility = $1 `;
        queryParams.push(facility);
    }

    sql += ` ORDER BY appointments.created_at DESC`;

    try {
        const result = await pool.query(sql, queryParams);
        const results = result.rows;

        // Calculate the stats for the dashboard cards
        const stats = { total: 0, pending: 0, completed: 0 };
        results.forEach(apt => {
            stats.total++;
            if (apt.status === 'Pending') stats.pending++;
            if (apt.status === 'Approved' || apt.status === 'Completed') stats.completed++;
        });

        res.render('admin-dashboard', {
            adminFacility: facility,
            appointments: results,
            stats: stats
        });
    } catch (err) {
        console.error("ADMIN DASHBOARD ERROR:", err.message);
        res.status(500).send("Database error.");
    }
});


// Admin Action: Approve or Decline Appointment
app.post('/api/admin/appointment/:id/:action', async (req, res) => {
    const adminId = req.session.adminId;
    if (!adminId) return res.redirect('/admin-login');

    const appointmentId = req.params.id;
    const action = req.params.action; // 'approve' or 'decline'

    let newStatus = 'Pending';
    if (action === 'approve') newStatus = 'Approved';
    if (action === 'decline') newStatus = 'Declined';

    try {
        await pool.query(`UPDATE appointments SET status = $1 WHERE id = $2`, [newStatus, appointmentId]);
    } catch (err) {
        console.error("STATUS UPDATE ERROR:", err.message);
    }

    res.redirect('/admin-dashboard');
});


// Secure Master Appointments Schedule
app.get('/admin-appointments', async (req, res) => {
    const adminId = req.session.adminId;
    if (!adminId) return res.redirect('/admin-login');

    const facility = req.session.adminFacility;

    let sql = `
        SELECT appointments.*, users.full_name, users.phone
        FROM appointments
        JOIN users ON appointments.patient_id = users.id
    `;
    const queryParams = [];

    if (facility !== 'All Facilities') {
        sql += ` WHERE appointments.facility = $1 `;
        queryParams.push(facility);
    }

    sql += ` ORDER BY appointments.appointment_date DESC`;

    try {
        const result = await pool.query(sql, queryParams);

        res.render('admin-appointments', {
            adminFacility: facility,
            appointments: result.rows
        });
    } catch (err) {
        console.error("ADMIN APPOINTMENTS ERROR:", err.message);
        res.status(500).send("Database error.");
    }
});


// Secure Patient Database
app.get('/admin-patients', async (req, res) => {
    const adminId = req.session.adminId;
    if (!adminId) return res.redirect('/admin-login');

    const facility = req.session.adminFacility;

    // Fetch all users plus their most recent appointment date and department
    const sql = `
        SELECT u.id, u.full_name, u.phone, u.dob,
            (SELECT appointment_date FROM appointments WHERE patient_id = u.id ORDER BY appointment_date DESC LIMIT 1) AS last_visit,
            (SELECT department FROM appointments WHERE patient_id = u.id ORDER BY appointment_date DESC LIMIT 1) AS last_department
        FROM users u
        ORDER BY u.created_at DESC
    `;

    try {
        const result = await pool.query(sql);

        res.render('admin-patients', {
            adminFacility: facility,
            patients: result.rows
        });
    } catch (err) {
        console.error("ADMIN PATIENTS ERROR:", err.message);
        res.status(500).send("Database error.");
    }
});


// Secure Facility Settings View
app.get('/admin-settings', (req, res) => {
    const adminId = req.session.adminId;
    if (!adminId) return res.redirect('/admin-login');

    res.render('admin-settings', { adminFacility: req.session.adminFacility });
});


// 9. Turn the server on
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`System Online: Server is running on http://localhost:${PORT}`);
});