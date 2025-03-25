const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
require('dotenv').config(); // stored in process.env
const path = require('path');
const http = require('http');
const PORT = process.env.PORT || 3000;

const app = express();
const server = http.createServer(app);
const io = new Server(server/*, { cors: { origin: '*' } }*/);

const { query, update } = require('./database');
let users;
let proposedProblems;
let problems;
let submissions;
(async () => {
    console.log('Started fetching');
    users = await update('users');
    proposedProblems = await update('proposedProblems');
    problems = await update('problems');
    console.log(problems);
    submissions = await update('submissions');
    submissions.forEach(submission => {
        submission.approved = new Set();
        submission.rejected = new Set();
    });
    console.log('Done fetching everything');
    server.listen(PORT, () => {
        console.log(`listening on port ${PORT}`);
    });
})();

function invalidInput(value) {
    return value === '' || value == undefined || value == null;
}

// app.set('view engine', 'ejs');
// app.use(express.static(path.join(__dirname, 'public')));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, 'public')));

app.use(express.json());

app.get('/', (req, res) => {
    res.redirect('/home');
});

app.get('/register', (req, res) => {
    res.redirect('signup');
});

app.get('/home', (req, res) => {
    res.render('home');
});

app.get('/about', (req, res) => {
    res.render('about');
});

app.get('/leaderboard', (req, res) => {
    const problemMapping = problems.reduce((map, problem) => {
        map[problem.id] = problem;
        return map;
    }, {});
    const leaderboard = users.map(user => {
        const hardestProblem = user.solvedProblems.reduce((accumulator, current) => {
            const problem = problemMapping[current];
            if (problem.difficulty > accumulator.difficulty || (problem.difficulty == accumulator.difficulty && new Date(current.date) > new Date(accumulator.date))) return problem;
            return accumulator;
        }, { name: 'none', difficulty: 0, date: new Date() });
        // console.log(user.rank);
        return {
            rank: user.rank,
            points: user.points,
            username: user.username,
            problemsSolved: user.solvedProblems.length,
            hardestProblem
        };
    });
    res.render('leaderboard', { users: leaderboard });
});

app.get('/problems', (req, res) => {
    console.log('number of problems', problems.length);
    res.render('problems', { problems });
});

app.get('/problems/does_not_exist', (req, res) => {
    res.status(404).render('message', { h1: 'Problem does not exist', redirectUrl: 'problems' });
});

app.get('/problems/:id', (req, res) => {
    if (!req?.body) return res.sendStatus(400);
    const problem = problems.find(problem => problem.id == req.params.id);
    if (!problem) return res.redirect('/problems/does_not_exist');
    res.render('problem', { problem });
});

const DISALLOWED_USERNAMES = ['admin', 'root', 'server', 'terminal', 'you', 'me', ' ', '.', '_'];

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', async (req, res) => {
    if (!req.body) return res.sendStatus(400);
    const { username, email, password } = req.body;
    if (invalidInput(username) || invalidInput(password)) return res.status(422).json({ message: 'username or password is empty' });
    if (username.length > 64) return res.status(422).json({ message: 'username too long' });
    if (DISALLOWED_USERNAMES.includes(username.toLowerCase())) return res.status(400).json({ message: 'Invalid username' });

    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await query(
        `INSERT INTO users (username, password, email)
        VALUES ($1, $2, $3)
        ON CONFLICT (username) DO NOTHING
        RETURNING username`,
        [username, hashedPassword, email || '']
    );
    if (result instanceof Error) return res.status(500).json({ errorCode: result.code });

    if (result.rows.length == 0) return res.status(409).json({ message: 'Username already exists.' });

    users = await update('users');
    console.log('Signed up', username);
    createAuthToken(result.rows[0].username, res);
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    if (!req?.body) return res.sendStatus(400);
    const { username, password } = req.body;
    if (invalidInput(username) || invalidInput(password)) return res.status(422).json({ message: 'username or password are empty' });
    
    let result = await query('SELECT username, password FROM users WHERE username = $1', [username]);
    if (result instanceof Error) return res.status(500).json({ errorCode: result.code });
    result = result?.rows;
    if (!result || result.length == 0) return res.status(401).json({ message: 'Incorrect username' });

    const match = await bcrypt.compare(password, result[0].password);
    if (!match) return res.status(401).json({ message: 'Incorrect password' });

    createAuthToken(username, res);
});

function createAuthToken(username, res) {
    const expiration = (process.env.JWT_EXPIRATION || '30') + 'min';
    const accessToken = jwt.sign({ username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: expiration });

    console.log('Creating auth token for', username);

    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: (process.env.JWT_EXPIRATION || 15) * 60000
    });
    res.json({ success: true });
    // TODO: Return the request back to the user in case of token expiration OR somehow alert the user client side that their token has expired on important pages (submissions)
    // Maybe (also) the cookie expiration could be max(till 12:00am, 1 hour)
}

function authenticateTokenHelper(token) {
    if (!token) return { isAuthenticated: false, message: 'no token' };
    
    try {
        const jwtUser = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        const user = users.find(user => user.username.toLowerCase() === jwtUser.username.toLowerCase());
        if (!user) return { isAuthenticated: false, message: 'user not found' };
        return { isAuthenticated: true, user };
    } catch (err) {
        return { isAuthenticated: false, message: err };
    }
};

app.get('/auth-status/check', (req, res) => {
    const token = req?.headers?.cookie?.replace('accessToken=', '');
    const authStatus = authenticateTokenHelper(token);
    res.json({ isAuthenticated: authStatus.isAuthenticated });
});

function authenticateToken(req, res, next) {
    const token = req?.headers?.cookie?.replace('accessToken=', '');
    const authStatus = authenticateTokenHelper(token);
    // console.log(authStatus?.user?.username || authStatus?.message);
    if (!authStatus.isAuthenticated) {
        return res.status(401).redirect('/login');
    }
    req.user = authStatus.user;
    next();
}

function isManager(req, res, next) {
    if (req.user.role != 'manager' && req.user.role != 'admin') return res.redirect('/invalid-permissions');
    next();
}

app.get('/invalid-permissions', (req, res) => {
    res.render('message', { h1: 'Invalid permissions', p: 'You do not have the permissions to do this.'});
})

app.get('/account', authenticateToken, (req, res) => {
    const queryUsername = req.query?.username;
    let user;
    let ownAccount = true;
    if (queryUsername) {
        user = users.find(user => user.username.toLowerCase() == queryUsername.toLowerCase());
        if (!user) return res.redirect('/account/user-not-found');
        ownAccount = false;
    } else user = req.user;
    // get problems user is verifying if applicable
    let verifyingProblems = [];
    if (user.verifyingProblems.length > 0 && ownAccount) {
        const mapping = problems.reduce((map, problem) => {
            map[problem.id] = problem.name;
            return map;
        }, {});
        verifyingProblems = user.verifyingProblems.map(id => [id, mapping[id]]);
    }
    const userProposedProblems = ownAccount ? proposedProblems.filter(problem => problem.creatorName.toLowerCase() == user.username.toLowerCase()) : [];

    let solvedProblems = user.solvedProblems.map(id => problems.find(problem => problem.id == id));
    solvedProblems = solvedProblems.sort((a, b) => b.difficulty - a.difficulty || new Date(b.timeCreated) - new Date(a.timeCreated));

    res.render('account', { ownAccount, ...user, solvedProblems, proposedProblems: userProposedProblems, verifyingProblems });
});

app.patch('/account/description', authenticateToken, async (req, res) => {
    if (req.body?.description == undefined) return res.status(400).json({ error: true, message: 'description is required' });
    let result = await query(`UPDATE users SET account_description = $1 WHERE id = $2`, [req.body.description, req.user.id]);
    if (result instanceof Error) return res.status(500).json({ error: true, message: 'database error' });
    req.user.accountDescription = req.body.description;
    res.json({ message: 'Successfully updated description' });
});

app.get('/account/user-not-found', (req, res) => {
    res.render('message', { h1: 'User not found', p: 'The user you are looking for does not exist.', redirectUrl: 'leaderboard' });
});

function isVerifierOfProblem(user, problemId) {
    return user.verifyingProblems.includes(parseInt(problemId));
}

app.get('/verifier/:id', authenticateToken, (req, res) => {
    // authorization
    if (!isVerifierOfProblem(req.user, req?.params?.id)) return res.redirect('/invalid-permissions');

    const filteredSubmissions = [];
    submissions.forEach(submission => {
        if (submission.problemId == req.params?.id) {
            const hasVoted = submission.approved.has(req.user.id) || submission.rejected.has(req.user.id);
            filteredSubmissions.push({ ...submission, approved: Array.from(submission.approved), rejected: Array.from(submission.rejected), hasVoted });
        }
    });
    res.render('verifier', { submissions: filteredSubmissions, verifierName: req.user.username });
});


let chatHistory = {};

io.on('connection', socket => {
    socket.on('join_room', room => {
        if (!isVerifierOfProblem(socket.user, room)) return socket.emit('error', 'You do not have permission to join this room');
        socket.join(room);
        chatHistory[room] = chatHistory[room] || [];
        socket.emit('join_room_response', chatHistory[room].map(element => ({
            username: element.username.toLowerCase() == socket.user.username.toLowerCase() ? 'you' : element.username,
            message: element.message,
            timestamp: element.timestamp
        })));
        // const message = {
        //     username: 'server',
        //     message: socket.user.username + ' has joined',
        //     timestamp: new Date()
        // }
        // chatHistory[room].push(message); 
        // socket.broadcast.to(room).emit('message', message);
    });
    socket.on('message', packet => {
        if (!packet) return socket.emit('error', 'no body');
        const { room, message } = packet;
        if (!room || !message || typeof message !== 'string') return socket.emit('error', 'invalid body');
        if (!socket.rooms.has(room)) return socket.emit('error', 'You do not have permission to message this room');
        const chatLog = {
            username: socket.user.username,
            message,
            timestamp: new Date()
        }
        socket.broadcast.to(room).emit('message', chatLog);
        chatHistory[room].push(chatLog); 
    });

    socket.on('vote', async packet => {
        if (!packet) return socket.emit('error', 'no body');
        const { room, submissionId, approving } = packet;
        if (!room || submissionId == undefined || approving == undefined) return socket.emit('error', 'invalid body');
        if (!socket.rooms.has(room)) return socket.emit('error', 'You do not have permission to use this room');
        const submission = submissions.find(submission => submission.id == submissionId);
        if (!submission) return socket.emit('error', 'submission was not found'); // should basically always be false as socket.rooms should only have valid rooms
        if (submission != 'pending') socket.emit('error', 'submissions has already been processed');
        const hasVoted = submission.approved.has(socket.user.id) || submission.rejected.has(socket.user.id);
        if (hasVoted) return socket.emit('error', 'You have already voted');

        const filteredSubmissions = submissions.filter(submission => submission.problemId == room);
        const totalVerifiers = users.reduce((count, user) => (isVerifierOfProblem(user, submission.problemId) ? count + 1 : count), 0);
        if (approving) {
            submission.approved.add(socket.user.id);
            if (submission.approved.size / totalVerifiers > 0.5 || (submission.rejected.size == 0 && submission.approved.size >= Math.min(totalVerifiers * 0.3, 4))) {
                let result = await query(`UPDATE submissions SET status = 'approved' WHERE id = $1`, [submission.id]);
                if (result instanceof Error) return socket.emit('error', 'Failed to update submission');
                submission.status = 'approved';

                const pointsEarned = problems.find(problem => problem.id == submission.problemId).difficulty;
                result = await query(`INSERT INTO solves (user_id, submission_id, points_granted) VALUES ($1, $2, $3)`, [socket.user.id, submission.id, pointsEarned]);
                if (result instanceof Error) return socket.emit('error', 'Failed to update score');
                // socket.user.score += pointsEarned;
                users = await update('users');
            }
        } else {
            submission.rejected.add(socket.user.id);
            if (submission.rejected.size / totalVerifiers >= 0.5 || (totalVerifiers > 4 && submission.rejected.size > submission.approved.size && submission.rejected.size >= Math.min(totalVerifiers * 0.33, 3))) {
                const result = await query(`UPDATE submissions SET status = 'rejected' WHERE id = $1`, [submission.id]);
                if (result instanceof Error) return socket.emit('error', 'Failed to update submission');
                submission.status = 'rejected';
            }
        }

        const userMap = users.reduce((map, user) => {
            map[user.id] = user.username;
            return map;
        }, {});

        io.in(room).emit('vote', [
            ...filteredSubmissions.map(submission => ({
                answer: submission.answer,
                username: submission.username,
                timeSubmitted: submission.timeSubmitted,
                proofLink: submission.proofLink,
                approved: Array.from(submission.approved).map(id => userMap[id]),
                rejected: Array.from(submission.rejected).map(id => userMap[id])
            }))
        ]);
        // io.in(room).emit('vote', { id, approving });

        // const chatLog = {
        //     username: 'server',
        //     message: `${socket.user.message} has ${approving ? 'approved' : 'rejected'} ${username}'s submission`,
        //     timestamp: new Date()
        // }
        // socket.broadcast.to(room).emit('message', chatLog);
        // chatHistory[room].push(chatLog); 
    });
});

io.use((socket, next) => {
    const cookies = socket.handshake.headers.cookie;
    const token = cookies?.split('; ').find(cookie => cookie.startsWith('accessToken='))?.split('=')[1];
    const authStatus = authenticateTokenHelper(token);

    if (!authStatus.isAuthenticated) {
        return next(new Error('Authentication failed: Invalid or missing token'));
    }

    socket.user = authStatus.user;

    next();
});


app.get('/manager', authenticateToken, isManager, (req, res) => {
    const proposedProblemsPending = [];
    proposedProblems.forEach(problem => {
        if (problem.status == 'pending') proposedProblemsPending.push({ id: problem.id, name: problem.name, description: problem.description, creatorName: problem.creatorName });
    });
    res.render('manager', { proposedProblems: proposedProblemsPending });
});

app.get('/manager/proposed-problems/success', (req, res) => {
    res.render('message', { h1: `Successfully ${req?.query?.approving === 'true' ? 'approved' : 'rejected'} proposed problem`, redirectUrl: 'manager' });
});

app.get('/manager/proposed-problems/does_not_exist', (req, res) => {
    res.status(404).render('message', { h1: 'Proposal does not exist or is no longer pending', redirectUrl: 'manager' });
});

app.get('invalid_permissions', (req, res) => {
    res.status(403).render('message', { h1: 'Invalid permissions', p: 'You do not have the necessary permissions to access this page.' })
});

app.get('/manager/proposed-problems/:id', authenticateToken, isManager, async (req, res) => {
    // TODO: Add feature where /edit-problem also edits existing problems (Right now it only approves/rejects proposals)
    
    const proposedProblem = proposedProblems.find(problem => problem.id == req.params.id && problem.status == 'pending');
    if (!proposedProblem) return res.redirect('/manager/proposed-problems/does_not_exist');
    res.render('edit-problem', { problem: proposedProblem });
});

app.post('/manager/proposed-problems/:id', authenticateToken, isManager, async (req, res) => {
    if (!req?.body) return res.status(400);
    const proposedProblem = proposedProblems.find(problem => problem.id == req.params.id && problem.status == 'pending');

    if (req.body.approving) {
        let { name, description, content, testable, difficulty } = req.body;
        if (!proposedProblem) return res.redirect('/manager/proposed-problems/does_not_exist');
        difficulty = parseInt(difficulty);
        if (invalidInput(name) || invalidInput(content) || invalidInput(testable) || isNaN(difficulty)) return res.status(422).json({ message: 'One or more required fields are empty' });
        if (problems.some(problem => problem.name == name)) return res.status(409).json({ message: 'Problem already exists' });
        if (difficulty <= 0) return res.status(400).json({ message: 'difficulty must be positive' });

        let result = await query(`INSERT INTO problems (name, description, content, time_created, testable, answer, creator_id, difficulty) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [name, description, content, proposedProblem.timeCreated, testable, proposedProblem.answer, proposedProblem.creatorId, difficulty]);
        if (result instanceof Error) return res.status(500).json({ errorCode: result.code, message: 'Failed to add to problems table' });
        if (result) problems = await update('problems');

        result = await query(`DELETE FROM proposed_problems WHERE id = $1`, [req.params.id]);
        if (result instanceof Error) return res.status(500).json({ errorCode: result.code, message: 'Failed to remove from proposed_problems' });

        proposedProblems = await update('proposedProblems');
    } if (req.body.reasoning !== null) {
        const result = await query(`UPDATE proposed_problems SET status = 'rejected', rejection_reasoning = $1 WHERE id = $2`, [req.body.reasoning || '', req.params.id]);
        if (result instanceof Error) return res.status(500).json({ errorCode: result.code, message: 'Failed to upload rejection' });
        proposedProblem.status = 'rejected';
        proposedProblem.rejectedReasoning = req.body.reasoning || '';
    } else return res.sendStatus(400);

    res.redirect(`/manager/proposed-problems/success?approving=${req.body.approving}`);
});

app.post('/manager/verifiers', authenticateToken, isManager, async (req, res) => {
    const { action, username, problemId } = req.body;
    if (!action || invalidInput(username) || problemId == undefined) return res.sendStatus(400);
    const user = users.find(user => user.username.toLowerCase() == username); // req.user is the manager (not relevant)
    if (!user) return res.json({ message: 'User not found' });
    const problem = problems.find(problem => problem.id == problemId);
    if (!problem) return res.json({ message: 'Problem not found' });

    const currentStat = await query(`SELECT 1 FROM verifiers WHERE user_id = $1 AND problem_id = $2 LIMIT 1`, [user.id, problemId]);
    if (currentStat instanceof Error) return res.status(500).json({ message: 'server error' });
    if (action == 'add') {
        if (currentStat.rows.length != 0) return res.json({ message: 'user is already added' });
        const result = await query(`INSERT INTO verifiers (user_id, problem_id) VALUES ($1, $2)`, [user.id, problemId])
        if (result instanceof Error) return res.status(500).json({ message: 'database error' });
        users = update('users');
        res.json({ message: 'Successfully added verifier' });
    } else if (action == 'remove') {
        if (currentStat.rows.length == 0) return res.json({ message: 'user is already removed' });
        const result = await query(`DELETE FROM verifiers WHERE user_id = $1 AND problem_id = $2`, [user.id, problemId]);
        if (result instanceof Error) return res.status(500).json({ message: 'database error' });
        users = update('users');
        res.json({ message: 'Successfully removed verifier' });
    } else return res.sendStatus(400);
});

const PENALTY_TIME = 18;

async function checkSubmissionCooldown(req, res, next) {
    const problem = problems.find(problem => problem.id == req.params.id);
    if (!problem) return res.redirect('/problems/does_not_exist');
    req.problem = problem;

    // ? Maybe update this later to check from local 'submissions'
    const lastSubmission = await query(`SELECT time_submitted, status FROM submissions WHERE user_id = $1 AND problem_id = $2 ORDER BY time_submitted DESC LIMIT 1`, [req.user.id, problem.id]);
    if (lastSubmission instanceof Error) return res.status(500).json({ message: 'Database error' });
    if (lastSubmission.rows.length == 0) return next();
    if (lastSubmission.rows[0].status == 'pending' || lastSubmission.rows[0].status == 'approved') return res.redirect('/submit/message?status=' + lastSubmission.rows[0].status);

    const lastSubmissionTime = new Date(lastSubmission.rows[0].time_submitted);
    const now = new Date();
    const timeSinceLastSubmission = now.getTime() - lastSubmissionTime.getTime();
    if (timeSinceLastSubmission < PENALTY_TIME * 3600000) {
        const remainingTime = PENALTY_TIME - Math.ceil(timeSinceLastSubmission / 3600000);
        return res.redirect('/submit/message?status=penalty&time=' + remainingTime);
    }
    next();
}

app.get('/submit/message', (req, res) => {
    switch (req?.query?.status) {
        case 'pending':
            return res.render('message', { h1: 'Please wait', p: 'Your previous answer has not yet been verified.', redirectUrl: 'account' });
        case 'approved':
            return res.render('message', { h1: 'Already Solved', p: 'I you have already solved this problem.', redirectUrl: 'problems' });
        case 'penalty':
            return res.status(429).render('message', { h1: 'Time penalty', p: `You have to wait ${req?.query?.time} hours before submitting again.`, redirectUrl: 'account' });
        default:
            return res.sendStatus(404);
    }
});

app.get('/submit/:id', authenticateToken, checkSubmissionCooldown, (req, res) => {
    const problem = problems.find(problem => problem.id == req.params.id);
    if (!problem) return res.redirect('/problems/does_not_exist');
    res.render('submit', { problem: req.problem });
});

app.post('/submit/:id', authenticateToken, checkSubmissionCooldown, async (req, res) => {
    const { answer, proof } = req.body;
    if (invalidInput(answer) || invalidInput(proof)) return res.sendStatus(422);

    const correct = req.body.answer == req.problem.answer || Number(req.body.answer) == Number(req.body.answer); // will (probably) be false if testable = false
    const status = req.problem.testable && !correct ? 'rejected' : 'pending';
    const result = await query(`INSERT INTO submissions (answer, user_id, problem_id, proof_link, status) VALUES ($1, $2, $3, $4, $5)`, [answer, req.user.id, req.problem.id, proof, status]);
    if (result instanceof Error) return res.status(500).json({ message: 'Database error' });
    submissions = (await update('submissions')).map((submission, i) => ({ ...submission, approved: submissions[i]?.approved || [], rejected: submissions[i]?.rejected || [] }));

    if (status == 'rejected') {
        res.json({ correct, message: `You answer was incorrect :( Please wait ${PENALTY_TIME} hours before resubmitting.` });
    } else if (req.problem.testable) {
        res.json({ correct: true, message: 'Correct! Please wait for the verifiers to approve your submission.' });
    } else {
        res.json({ correct: 'pending', message: 'Please wait for a response from the verifiers.' });
    }
});

app.get('/propose-problem', authenticateToken, (req, res) => {
    res.render('propose-problem');
});

app.post('/propose-problem', authenticateToken, async (req, res) => {
    const { name, description, content, testable, answer, difficulty } = req.body;
    if (invalidInput(name) || invalidInput(content) || testable == undefined) return res.status(422).json({ message: 'One or more required fields are empty' });
    const numberedDifficulty = parseInt(difficulty);

    const result = await query(`INSERT INTO proposed_problems (name, description, content, testable, answer, difficulty, creator_id) VALUES ($1, $2, $3, $4, $5, $6, $7)`, [name, description, content, testable, answer.trim(), (Number.isInteger(numberedDifficulty) && numberedDifficulty > 0) ? numberedDifficulty : null, req.user.id]);
    if (result instanceof Error) return res.status(500).json({ message: 'Database error' });
    proposedProblems = await update('proposedProblems');

    res.redirect('/propose-problem/success');
});

app.get('/propose-problem/success', (req, res) => {
    res.render('message', { h1: 'Proposed problem submitted successfully', p: 'A manager will approve or reject your problem soon. Please note that anything in your submission can be altered, although you will still receive credit for it.' })
});