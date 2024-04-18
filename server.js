import express from 'express';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'crypto';
import pg from 'pg';
const { Pool } = pg;
import { nanoid } from 'nanoid';

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'secret_messages',
    password: 'postgres',
    port: 5432,
});

app.get('/', (req, res) => {
    res.send('Welcome to the Secret Message Service!');
});

app.post('/message', async (req, res) => {
    const { password, message } = req.body;
    const salt = crypto.randomBytes(16).toString('hex');
    const key = crypto.scryptSync(password, salt, 24);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-192-cbc', key, iv);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const id = nanoid(6);

    await pool.query('INSERT INTO messages (id, salt, iv, message) VALUES ($1, $2, $3, $4)', [id, salt, iv.toString('hex'), encrypted]);
    res.send({ id });
});

app.get('/message/:id', async (req, res) => {
    const { id } = req.params;
    const { password } = req.query;

    const result = await pool.query('SELECT salt, iv, message FROM messages WHERE id = $1', [id]);
    if (result.rows.length == 0) {
        return res.status(404).send('Message not found');
    }

    const { salt, iv, message } = result.rows[0];
    const key = crypto.scryptSync(password, salt, 24);
    const decipher = crypto.createDecipheriv('aes-192-cbc', key, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(message, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    res.send(decrypted);
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
