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
    users = await update('users');
    proposedProblems = await update('proposedProblems');
    problems = await update('problems');
    submissions = await update('submissions');
    submissions.forEach(submission => {
        submission.approved = [];
        submission.rejected = [];
    });
    console.log('Done fetching');
})();

app.set('view engine', 'ejs');
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

app.get('/leaderboard', (req, res) => {
    res.render('leaderboard');
});

app.get('/problems', (req, res) => {
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

const DISALLOWED_USERNAMES = ['admin', 'root', 'server', 'terminal', 'you', ' ', '.', '_'];

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', async (req, res) => {
    if (!req.body) return res.sendStatus(400);
    const { username, email, password } = req.body;
    if (!username || !password) return res.status(422).json({ message: 'username or password is empty' });
    if (DISALLOWED_USERNAMES.includes(username.toLowerCase())) return res.status(400).json({ message: 'Invalid username' });

    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await query(
        `INSERT INTO users (username, password, email)
        VALUES ($1, $2, $3)
        ON CONFLICT (username) DO NOTHING
        RETURNING username`,
        [username, hashedPassword, email]
    );
    if (result instanceof Error) return res.status(500).json({ errorCode: result.code });

    if (result.rows.length == 0) return res.status(409).json({ message: 'Username already exists.' });

    users = await update('users');
    createAuthToken(result.rows[0].username, res);
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    if (!req?.body) return res.sendStatus(400);
    const { username, password } = req.body;
    if (!username || !password) return res.status(422).json({ message: 'username or password are empty' });
    
    let result = await query('SELECT username, password FROM users WHERE username = $1', [username]);
    if (result instanceof Error) return res.status(500).json({ errorCode: result.code });
    result = result?.rows;
    if (!result || result.length == 0) return res.status(401).json({ message: 'Invalid username' });

    const match = await bcrypt.compare(password, result[0].password);
    if (!match) return res.status(401).json({ message: 'Invalid password' });

    createAuthToken(username, res);
});

function createAuthToken(username, res) {
    const expiration = (process.env.JWT_EXPIRATION || '15') + 'min';
    // console.log(expiration, username);
    const accessToken = jwt.sign({ username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: expiration });
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
    console.log(authStatus?.user?.username || authStatus?.message);
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
    const userProposedProblems = proposedProblems.filter(problem => problem.creatorName.toLowerCase() == req.user.username.toLowerCase());
    // get problems user is verifying if applicable
    let verifyingProblems = [];
    if (req.user.verifyingProblems.length > 0) {
        const mapping = problems.reduce((map, problem) => {
            map[problem.id] = problem.name;
            return map;
        }, {});
        verifyingProblems = req.user.verifyingProblems.map(id => [id, mapping[id]]);
    }
    res.render('account', { ...req.user, proposedProblems: userProposedProblems, verifyingProblems });
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
            const hasVoted = submission.approved.includes(req.user.id) || submission.rejected.includes(req.user.id);
            filteredSubmissions.push({ ...submission, hasVoted });
        }
    });
    res.render('verifier', { submissions: filteredSubmissions });
});

app.post('/verifier/:id', authenticateToken, async (req, res) => {
    if (!req?.body) return res.sendStatus(400);
    // authorization
    if (!isVerifierOfProblem(req.user, req?.params?.id)) return res.redirect('/invalid-permissions');

    const { id, approving } = req.body;
    if (id == undefined || approving == undefined) return res.sendStatus(422);
    const submission = submissions.find(submission => submission.id == parseInt(id));
    if (!submission) return res.status(409).json({ error: true, message: 'submission was not found' });
    const hasVoted = submission.approved.includes(req.user.id) || submission.rejected.includes(req.user.id);
    if (hasVoted) return res.status(422).json({ error: true, message: 'You have already voted' });
    const totalVerifiers = users.reduce((count, user) => (isVerifierOfProblem(user, submission.problemId) ? count + 1 : count), 0);
    if (approving) {
        submission.approved.push(req.user.id);
        if ((submission.rejected.length == 0 && submission.approved >= Math.min(totalVerifiers * 0.3, 5)) || submission.approved / totalVerifiers > 0.5) {
            const result = await query(`UPDATE submissions SET status = 'approved' WHERE id = $1`, [submission.id]);
            if (result instanceof Error) return res.status(500).json({ errorCode: result.code, message: 'Failed to upload rejection' });
            submission.status = 'approved';
        }
    } else {
        submission.rejected.push(req.user.id);
        if (submission.rejected.length / totalVerifiers >= 0.5 || (totalVerifiers > 4 && submission.rejected.length > submission.approved.length)) {
            const result = await query(`UPDATE submissions SET status = 'rejected' WHERE id = $1`, [submission.id]);
            if (result instanceof Error) return res.status(500).json({ errorCode: result.code, message: 'Failed to upload rejection' });
            submission.status = 'rejected';
        }
    }
    console.log(submission, totalVerifiers);
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
        if (!room || !message) return socket.emit('error', 'invalid body');
        if (!socket.rooms.has(room)) return socket.emit('error', 'You do not have permission to message this room');
        const chatLog = {
            username: socket.user.username,
            message,
            timestamp: new Date()
        }
        socket.broadcast.to(room).emit('message', chatLog);
        chatHistory[room].push(chatLog); 
    });

    socket.on('vote', packet => {
        if (!packet) return socket.emit('error', 'no body');
        const { room, id, approving } = packet;
        if (!room || id == undefined || approving == undefined) return socket.emit('error', 'invalid body');
        if (!socket.rooms.has(room)) return socket.emit('error', 'You do not have permission to use this room');
        const chatLog = {
            username: 'server',
            message: `${socket.user.message} has ${approving ? 'approved' : 'rejected'} ${username}'s submission`,
            timestamp: new Date()
        }
        socket.broadcast.to(room).emit('message', chatLog);
        io.in(room).emit('vote', { id, approving });
        chatHistory[room].push(chatLog); 
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

// io.use((socket, next) => {
//     const cookies = socket.handshake.headers.cookie;
//     const token = cookies?.split('; ').find(cookie => cookie.startsWith('accessToken='))?.split('=')[1];

//     if (!token) {
//         return next(new Error('Authentication failed: No token provided'));
//     }

//     try {
//         const jwtUser = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
//         const user = users.find(user => user.username.toLowerCase() === jwtUser.name.toLowerCase());
//         if (!user) {
//             return next(new Error('Authentication failed: User not found'));
//         }
//         socket.user = user;

//         next();
//     } catch (err) {
//         return next(new Error('Authentication failed: Invalid token'));
//     }
// });



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
        const { name, description, content, testable, difficulty } = req.body;
        if (!proposedProblem) return res.redirect('/manager/proposed-problems/does_not_exist');
        if (!name || !content || testable === undefined || difficulty === undefined) return res.status(422).json({ message: 'One or more required fields are empty' });

        let result = await query(`INSERT INTO problems (name, description, content, time_created, testable, answer, creator_id, difficulty) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [name, description, content, proposedProblem.timeCreated, testable, proposedProblem.answer, proposedProblem.creatorId, difficulty]);
        if (result instanceof Error) return res.status(500).json({ errorCode: result.code, message: 'Failed to add to problems table' });
        problems = await update('problems');
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
    if (!action || !username || problemId === undefined) return res.sendStatus(400);
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
    if (lastSubmission.rows[0].status == 'pending' || lastSubmission.rows[0].status == 'approved') return res.redirect('/message?status=' + lastSubmission.rows[0].status);

    const lastSubmissionTime = new Date(lastSubmission.rows[0].time_submitted);
    const now = new Date();
    const timeSinceLastSubmission = now.getTime() - lastSubmissionTime.getTime();
    console.log(timeSinceLastSubmission, lastSubmissionTime)
    if (timeSinceLastSubmission < PENALTY_TIME * 3600000) {
        const remainingTime = PENALTY_TIME - Math.ceil(timeSinceLastSubmission / 3600000);
        return res.redirect('/submit/message?status=penalty&time=' + remainingTime);
    }
    next();
}

// app.get('/submit', authenticateToken, (req, res) => {
//     res.render('submit');
// });

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
    if (!answer || !proof) return res.sendStatus(422);

    const correct = req.body.answer == req.problem.answer; // will (probably) be false if testable = false
    const status = req.problem.testable && !correct ? 'rejected' : 'pending';
    const result = await query(`INSERT INTO submissions (answer, user_id, problem_id, proof_link, status) VALUES ($1, $2, $3, $4, $5)`, [answer, req.user.id, req.problem.id, proof, status]);
    if (result instanceof Error) return res.status(500).json({ message: 'Database error' });
    submissions = update('submissions');
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
    const { name, description, content, testable, answer } = req.body;
    if (!name || !content || testable === undefined || !answer) return res.status(422).json({ message: 'One or more required fields are empty' });

    const result = await query(`INSERT INTO proposed_problems (name, description, content, testable, answer, creator_id) VALUES ($1, $2, $3, $4, $5, $6)`, [name, description, content, testable, answer.trim(), req.user.id]);
    if (result instanceof Error) return res.status(500).json({ message: 'Database error' });
    proposedProblems = await update('proposedProblems');

    res.redirect('/propose-problem/success');
});

app.get('/propose-problem/success', (req, res) => {
    res.render('message', { h1: 'Proposed problem submitted successfully', p: 'A manager will approve or reject your problem soon. Please note that anything in your submission can be altered, although you will still receive credit for it.' })
});

server.listen(PORT, () => {
    console.log(`listening on port ${PORT}`);
});