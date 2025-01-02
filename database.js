const { Pool } = require('pg');
require('dotenv').config(); // stored in process.env
const pool = new Pool({
    user: process.env.PGUSER,
    host: process.env.PGHOST,
    database: process.env.DATABASE,
    password: process.env.PGPASSWORD,
    port: process.env.PGPORT,
    ssl: {
        require: true
    }
});
// const client = new Client({ ssl: true });

async function query(query, parameters) {
    try {
        const res = await pool.query(query, parameters);
        return res;
    } catch (error) {
        console.error(error);
        return error;
    }
}


async function update(table) {
    let result;
    switch (table) {
        case 'users':
            result = await query('SELECT id, username, date_joined, role, account_description FROM users');
            if (result instanceof Error) {
                console.error(result);
                return;
            } 
            return result.rows.map((row, i) => {
                return {
                    id: row.id,
                    username: row.username,
                    rank: i + 1,
                    dateJoined: row.date_joined,
                    role: row.role,
                    accountDescription: row.account_description
                }
            });
        case 'proposedProblems':   
            result = await query('SELECT proposed_problems.*, users.username AS username FROM proposed_problems JOIN users ON proposed_problems.creator_id = users.id ORDER BY time_created');
            if (result instanceof Error) {
                console.error(result);
                return;
            } 
            return result.rows.map((row, i) => {
                return {
                    id: row.id,
                    name: row.name,
                    description: row.description,
                    content: row.content,
                    testable: row.testable,
                    answer: row.answer,
                    timeCreated: row.time_created,
                    creatorId: row.creator_id,
                    creatorName: row.username,
                    status: row.status,
                    rejectionReasoning: row.rejection_reasoning
                }
            });
        case 'problems':
            result = await query(`
                SELECT problems.*, users.username AS username FROM problems JOIN users ON problems.creator_id = users.id ORDER BY difficulty DESC`
            );
            if (result instanceof Error) {
                console.error(result);
                return;
            } 
            return result.rows.map(row => {
                return {
                    id: row.id,
                    name: row.name,
                    description: row.description,
                    content: row.content,
                    timeCreated: row.time_created,
                    testable: row.testable,
                    answer: row.answer,
                    creatorId: row.creator_id,
                    creatorName: row.username,
                    difficulty: row.difficulty
                }
            });
        default:
            console.error('Invalid table:', table);
    }
}

module.exports = { query, update };