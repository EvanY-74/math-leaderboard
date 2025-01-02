const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // stored in process.env
const PORT = process.env.PORT || 3000;

const PENALTY_TIME = 18;

const { query, update } = require('./database');
let users;
let proposedProblems;
let problems;
(async () => {
    users = await update('users');
    proposedProblems = await update('proposedProblems');
    problems = await update('problems');
})();

app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public'));
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

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', async (req, res) => {
    if (!req.body) return res.sendStatus(400);
    const { username, email, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'username or password is empty' });

    
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
    if (!username || !password) return res.status(400).json({ message: 'username or password are empty' });
    
    let result = await query('SELECT username, password FROM users WHERE username = $1', [username]);
    if (result instanceof Error) return res.status(500).json({ errorCode: result.code });
    result = result?.rows;
    if (!result || result.length == 0) return res.status(401).json({ message: 'Invalid username' });

    const match = await bcrypt.compare(password, result[0].password);
    if (!match) res.status(401).json({ message: 'Invalid password' });

    createAuthToken(username, res);
});

function createAuthToken(username, res) {
    const expiration = (process.env.JWT_EXPIRATION || '15') + 'min';
    // console.log(expiration, username);
    const accessToken = jwt.sign({ name: username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: expiration });
    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: (process.env.JWT_EXPIRATION || 15) * 60000
    });
    res.json({ success: true });
}

function authenticateToken(req, res, next) {
    const token = req?.headers?.cookie?.replace('accessToken=', '');
    if (!token) return res.status(401).redirect('/login');

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).redirect('/login');
        // TODO: Return the request back to the user in case of token expiration OR somehow alert the user client side that their token has expired on important pages (submissions)
        // Maybe (also) the cookie expiration could be max(till 12:00am, 1 hour)
        const dbUser = users.find(dbUser => dbUser.username.toLowerCase() == user.name.toLowerCase());
        if (!dbUser) return res.status(403).redirect('/login');
        req.user = dbUser;
        next();
    });
}

function isManager(req, res, next) {
    if (!req.user) return res.status(500).redirect('/login');
    if (req.user.role != 'manager' && req.user.role != 'admin') return res.redirect('/manager/invalid_permissions');
    next();
}

app.get('/account', authenticateToken, (req, res) => {
    const userProposedProblems = proposedProblems.filter(problem => problem.creatorName == req.user.username);
    res.render('account', { ...req.user, proposedProblems: userProposedProblems });
});

app.get('/manager', authenticateToken, isManager, async (req, res) => {
    const proposedProblemsPending = [];
    proposedProblems.forEach(problem => {
        if (problem.status == 'pending') proposedProblemsPending.push({ id: problem.id, name: problem.name, description: problem.description, creatorName: problem.creatorName });
    });
    res.render('manager', { proposedProblems: proposedProblemsPending });
});

app.get('/manager/success', (req, res) => {
    res.render('message', { h1: `Successfully ${req?.query?.approving === 'true' ? 'approved' : 'rejected'} proposed problem`, redirectUrl: 'manager' });
});

app.get('/manager/does_not_exist', (req, res) => {
    res.status(404).render('message', { h1: 'Proposal does not exist or is no longer pending', redirectUrl: 'manager' });
});

app.get('/manager/invalid_permissions', (req, res) => {
    res.status(403).render('message', { h1: 'Invalid permissions', p: 'You do not have the necessary permissions to access this page.' })
});

app.get('/manager/:id', authenticateToken, isManager, async (req, res) => {
    // TODO: Add feature where /edit_problem also edits existing problems (Right now it only approves/rejects proposals)
    
    const proposedProblem = proposedProblems.find(problem => problem.id == req.params.id && problem.status == 'pending');
    if (!proposedProblem) return res.redirect('/manager/does_not_exist');
    res.render('edit_problem', { problem: proposedProblem });
});

app.post('/manager/:id', authenticateToken, isManager, async (req, res) => {
    const proposedProblem = proposedProblems.find(problem => problem.id == req.params.id && problem.status == 'pending');

    if (req.body.approving) {
        const { name, description, content, testable, difficulty } = req.body;
        if (!proposedProblem) return res.redirect('/manager/does_not_exist');
        if (!name || !content || testable === undefined || difficulty === undefined) return res.status(400).json({ message: 'One or more required fields are empty' });

        let result = await query(`INSERT INTO problems (name, description, content, time_created, testable, answer, creator_id, difficulty) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [name, description, content, proposedProblem.timeCreated, testable, proposedProblem.answer, proposedProblem.creatorId, difficulty]);
        if (result instanceof Error) return res.status(500).json({ errorCode: result.code, message: 'Failed to add to problems table' });
        problems = await update('problems');
        result = await query(`DELETE FROM proposed_problems WHERE id = $1`, [req.params.id]);
        if (result instanceof Error) return res.status(500).json({ errorCode: result.code, message: 'Failed to remove from proposed_problems' });
        proposedProblems = await update('proposedProblems');
    } if (req.body.reasoning !== null) {
        let result = await query(`UPDATE proposed_problems SET status = 'rejected', rejection_reasoning = $1 WHERE id = $2`, [req.body.reasoning || '', req.params.id]);
        if (result instanceof Error) return res.status(500).json({ errorCode: result.code, message: 'Failed to upload rejection' });
        proposedProblem.status = 'rejected';
        proposedProblem.rejectedReasoning = req.body.reasoning;
    } else return res.sendStatus(400);

    res.redirect(`/manager/success?approving=${req.body.approving}`);
    // res.json({ redirectUrl: `/manager/success?approving=${req.body.approving}` });
});

async function checkSubmissionCooldown(req, res, next) {
    const problem = problems.find(problem => problem.id == req.params.id);
    if (!problem) return res.redirect('/problems/does_not_exist');
    req.problem = problem;

    const lastSubmission = await query(`SELECT time_submitted, status FROM submissions WHERE user_id = $1 AND problem_id = $2 ORDER BY time_submitted DESC LIMIT 1`, [req.user.id, problem.id]);
    if (lastSubmission instanceof Error) return res.status(500).json({ message: 'Database error' });
    if (lastSubmission.rows.length == 0) return next();
    if (lastSubmission.rows[0].status == 'pending' || lastSubmission.rows[0].status == 'approved') return res.redirect('/message?status=' + lastSubmission.rows[0].status);
    // if (lastSubmission.rows[0].status == 'approved') return res.redirect('/message?status=approved');

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
    if (!answer || !proof) return res.sendStatus(400);

    const correct = req.body.answer == req.problem.answer; // will (probably) be false if testable = false
    const status = req.problem.testable && !correct ? 'rejected' : 'pending';
    const result = await query(`INSERT INTO submissions (answer, user_id, problem_id, proof_link, status) VALUES ($1, $2, $3, $4, $5)`, [answer, req.user.id, req.problem.id, proof, status]);
    if (result instanceof Error) return res.status(500).json({ message: 'Database error' });
    if (status == 'rejected') {
        res.json({ correct, message: `You answer was incorrect :( Please wait ${PENALTY_TIME} hours before resubmitting.` });
    } else if (req.problem.testable) {
        res.json({ correct: true, message: 'Correct! Please wait for the verifiers to approve your submission.' });
    } else {
        res.json({ correct: 'pending', message: 'Please wait for a response from the verifiers.' });
    }
});

app.get('/propose_problem', authenticateToken, (req, res) => {
    res.render('propose_problem');
});

app.post('/propose_problem', authenticateToken, async (req, res) => {
    const { name, description, content, testable, answer } = req.body;
    if (!name || !content || testable === undefined || !answer) return res.status(400).json({ message: 'One or more required fields are empty' });

    const result = await query(`INSERT INTO proposed_problems (name, description, content, testable, answer, creator_id) VALUES ($1, $2, $3, $4, $5, $6)`, [name, description, content, testable, answer.trim(), req.user.id]);
    if (result instanceof Error) return res.status(500).json({ message: 'Database error' });
    proposedProblems = await update('proposedProblems');

    res.redirect('/propose_problem/success');
    // res.json({ redirectUrl: '/propose_problem/success' });
});

app.get('/propose_problem/success', (req, res) => {
    res.render('message', { h1: 'Proposed problem submitted successfully', p: 'A manager will approve or reject your problem soon. Please note that anything in your submission can be altered, although you will still receive credit for it.' })
});

app.listen(PORT, () => {
    console.log(`listening on port ${PORT}`);
});