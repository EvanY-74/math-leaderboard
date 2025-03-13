const { Pool } = require('pg');
require('dotenv').config(); // stored in process.env
const pool = new Pool({
    user: process.env.PGUSER,
    host: process.env.PGHOST,
    database: process.env.PGDATABASE,
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
            result = await query(`
                SELECT 
                    users.id, 
                    username, 
                    date_joined, 
                    role, 
                    account_description,
                    COALESCE(ARRAY_AGG(verifiers.problem_id), '{}') AS problem_ids,
                    COALESCE(SUM(solves.points_granted), 0) AS points,
                    COALESCE(
                        ARRAY_AGG(solves.problem_id ORDER BY solves.time_approved DESC), 
                        '{}'
                    ) AS solved_problems
                FROM 
                    users
                LEFT JOIN 
                    verifiers ON users.id = verifiers.user_id
                LEFT JOIN 
                    solves ON users.id = solves.user_id
                GROUP BY 
                    users.id
                ORDER BY 
                    points DESC,
                    username ASC;
            `);
            if (result instanceof Error) {
                console.error(result);
                return;
            } 
            let users = result.rows.map((row, i) => ({
                id: row.id,
                username: row.username,
                points: row.points,
                rank: i + 1,
                dateJoined: row.date_joined,
                role: row.role,
                accountDescription: row.account_description,
                solvedProblems: (row.solved_problems[0] == null ? [] : row.solved_problems) || [],
                verifyingProblems: (row.problem_ids[0] == null ? [] : row.problem_ids) || [],
            })) || [];
            console.log('before ranking', users?.length, result.rows?.length);
            // users = rankUsers(users);
            console.log('after ranking', users?.length);
            return users;
        case 'proposedProblems':   
            result = await query('SELECT proposed_problems.*, users.username FROM proposed_problems JOIN users ON proposed_problems.creator_id = users.id ORDER BY time_created');
            if (result instanceof Error) {
                console.error(result);
                return;
            } 
            return result.rows.map((row, i) => ({
                id: row.id,
                name: row.name,
                description: row.description,
                content: row.content,
                testable: row.testable,
                answer: row.answer,
                difficulty: row.difficulty,
                timeCreated: row.time_created,
                creatorId: row.creator_id,
                creatorName: row.username,
                status: row.status,
                rejectionReasoning: row.rejection_reasoning
            })) || [];
        case 'problems':
            result = await query(`SELECT problems.*, users.username FROM problems JOIN users ON problems.creator_id = users.id ORDER BY difficulty DESC`);
            if (result instanceof Error) {
                console.error(result);
                return;
            } 
            return result.rows.map(row => ({
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
            })) || [];
        case 'submissions':
            result = await query(`SELECT submissions.id, time_submitted, answer, proof_link, users.username, problem_id FROM submissions JOIN users ON submissions.user_id = users.id WHERE status = 'pending' ORDER BY time_submitted`);
            if (result instanceof Error) {
                console.error(result);
                return;
            } 
            return result.rows.map(row => ({
                id: row.id,
                username: row.username,
                problemId: row.problem_id,
                timeSubmitted: row.time_submitted,
                answer: row.answer,
                proofLink: row.proof_link,
            })) || [];
        default:
            console.error('Invalid table:', table);
    }
}

function rankUsers(users, preSorted = true) {
    let sortedUsers = [...users];
    if (!preSorted) sortedUsers.sort((a, b) => b.points - a.points);

    let currentRank = 1;
    let currentPoints = -Infinity;
    sortedUsers.forEach((user, i) => {
        if (user.points == currentPoints) {
            user.rank = currentRank;
        } else {
            user.rank = i + 1;
            currentRank = user.rank;
            currentPoints = user.points;
        }
    });
    return sortedUsers;
}

module.exports = { query, update };