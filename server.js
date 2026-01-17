require("dotenv").config();
const jwt = require("jsonwebtoken");
const marked = require("marked");
const sanitizeHTML = require("sanitize-html");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const express = require("express");
const db = require("better-sqlite3")("devlog.db");
db.pragma("journal_mode = WAL");

// database setup here
const createTables = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
    `
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    body TEXT NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users (id)
    )
  `
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS sublogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    body TEXT NOT NULL,
    authorid INTEGER,
    logid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users (id),
    FOREIGN KEY (logid) REFERENCES logs (id)
    )
  `
  ).run();
});

createTables();

// database setup ends here

const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(cookieParser());

app.use(function (req, res, next) {
  // make our markdown function available
  res.locals.filterUserHTML = function (content) {
    return sanitizeHTML(marked.parse(content), {
      allowedTags: [
        "p",
        "br",
        "ul",
        "li",
        "ol",
        "strong",
        "bold",
        "i",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
      ],
      allowedAttributes: {},
    });
  };

  res.locals.errors = [];

  // try to decode incoming cookie
  try {
    const decoded = jwt.verify(
      req.cookies.devlogAuthToken,
      process.env.JWTSECRET
    );
    req.user = decoded;
  } catch (err) {
    req.user = false;
  }

  res.locals.user = req.user;
  console.log(req.user);

  next();
});

app.get("/", (req, res) => {
  if (req.user) {
    const logsStatement = db.prepare(
      "SELECT logs.*, users.username FROM logs INNER JOIN users ON logs.authorid = users.id ORDER BY logs.createdDate DESC"
    );
    const logs = logsStatement.all();
    return res.render("dashboard", { logs });
  }

  res.render("homepage");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/logout", (req, res) => {
  res.clearCookie("devlogAuthToken");
  res.redirect("/");
});

app.post("/login", (req, res) => {
  let errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  if (req.body.username.trim() == "") errors = ["Invalid username / password."];
  if (req.body.password == "") errors = ["Invalid username / password."];

  if (errors.length) {
    return res.render("login", { errors });
  }

  const userInQuestionStatement = db.prepare(
    "SELECT * FROM users WHERE USERNAME = ?"
  );
  const userInQuestion = userInQuestionStatement.get(req.body.username);

  if (!userInQuestion) {
    errors = ["Invalid username / password."];
    return res.render("login", { errors });
  }

  const matchOrNot = bcrypt.compareSync(
    req.body.password,
    userInQuestion.password
  );
  if (!matchOrNot) {
    errors = ["Invalid username / password."];
    return res.render("login", { errors });
  }

  const authToken = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skyColor: "blue",
      userid: userInQuestion.id,
      username: userInQuestion.username,
    },
    process.env.JWTSECRET
  );

  res.cookie("devlogAuthToken", authToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  res.redirect("/");
});

function mustBeLoggedIn(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect("/");
}

app.get("/create-log", mustBeLoggedIn, (req, res) => {
  res.render("create-log");
});

function sharedLogValidation(req) {
  const errors = [];

  if (typeof req.body.title !== "string") req.body.title = "";
  if (typeof req.body.body !== "string") req.body.body = "";

  // trim - sanitize or strip out html
  req.body.title = sanitizeHTML(req.body.title.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });
  req.body.body = sanitizeHTML(req.body.body.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  if (!req.body.title) errors.push("You must provide a title.");
  if (!req.body.body) errors.push("You must provide content.");

  return errors;
}

app.get("/edit-log/:id", mustBeLoggedIn, (req, res) => {
  // try to look up the log in question
  const statement = db.prepare("SELECT * FROM logs WHERE id = ?");
  const log = statement.get(req.params.id);

  if (!log) {
    return res.redirect("/");
  }

  // if you're not the author, redirect to homepage
  if (log.authorid !== req.user.userid) {
    return res.redirect("/");
  }

  // otherwise, render the edit log template
  res.render("edit-log", { log });
});

app.post("/edit-log/:id", mustBeLoggedIn, (req, res) => {
  // try to look up the log in question
  const statement = db.prepare("SELECT * FROM logs WHERE id = ?");
  const log = statement.get(req.params.id);

  if (!log) {
    return res.redirect("/");
  }

  // if you're not the author, redirect to homepage
  if (log.authorid !== req.user.userid) {
    return res.redirect("/");
  }

  const errors = sharedLogValidation(req);

  if (errors.length) {
    return res.render("edit-log", { errors });
  }

  const updateStatement = db.prepare(
    "UPDATE logs SET title = ?, body = ? WHERE id = ?"
  );
  updateStatement.run(req.body.title, req.body.body, req.params.id);

  res.redirect(`/log/${req.params.id}`);
});

app.get("/edit-sublog/:id", mustBeLoggedIn, (req, res) => {
  // try to look up the sublog in question
  const statement = db.prepare("SELECT * FROM sublogs WHERE id = ?");
  const sublog = statement.get(req.params.id);

  if (!sublog) {
    return res.redirect("/");
  }

  // if you're not the author, redirect to homepage
  if (sublog.authorid !== req.user.userid) {
    return res.redirect("/");
  }

  // otherwise, render the edit sublog template
  res.render("edit-sublog", { sublog });
});

app.post("/edit-sublog/:id", mustBeLoggedIn, (req, res) => {
  // try to look up the sublog in question
  const statement = db.prepare("SELECT * FROM sublogs WHERE id = ?");
  const sublog = statement.get(req.params.id);

  if (!sublog) {
    return res.redirect("/");
  }

  // if you're not the author, redirect to homepage
  if (sublog.authorid !== req.user.userid) {
    return res.redirect("/");
  }

  const errors = [];

  if (typeof req.body.body !== "string") req.body.body = "";

  req.body.body = sanitizeHTML(req.body.body.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  if (!req.body.body) errors.push("You must provide content.");

  if (errors.length) {
    return res.render("edit-sublog", { errors, sublog });
  }

  const updateStatement = db.prepare(
    "UPDATE sublogs SET body = ? WHERE id = ?"
  );
  updateStatement.run(req.body.body, req.params.id);

  // redirect to the log page
  const logStatement = db.prepare("SELECT logid FROM sublogs WHERE id = ?");
  const logId = logStatement.get(req.params.id).logid;
  res.redirect(`/log/${logId}`);
});

app.post("/delete-sublog/:id", mustBeLoggedIn, (req, res) => {
  // try to look up the sublog in question
  const statement = db.prepare("SELECT * FROM sublogs WHERE id = ?");
  const sublog = statement.get(req.params.id);

  if (!sublog) {
    return res.redirect("/");
  }

  // if you're not the author, redirect to homepage
  if (sublog.authorid !== req.user.userid) {
    return res.redirect("/");
  }

  const deleteStatement = db.prepare("DELETE FROM sublogs WHERE id = ?");
  deleteStatement.run(req.params.id);

  res.redirect(`/log/${sublog.logid}`);
});

app.post("/delete-log/:id", mustBeLoggedIn, (req, res) => {
  // try to look up the log in question
  const statement = db.prepare("SELECT * FROM logs WHERE id = ?");
  const log = statement.get(req.params.id);

  if (!log) {
    return res.redirect("/");
  }

  // if you're not the author, redirect to homepage
  if (log.authorid !== req.user.userid) {
    return res.redirect("/");
  }

  // Delete all sublogs associated with this log first
  const deleteSublogsStatement = db.prepare(
    "DELETE FROM sublogs WHERE logid = ?"
  );
  deleteSublogsStatement.run(req.params.id);

  // Then delete the main log
  const deleteStatement = db.prepare("DELETE FROM logs WHERE id = ?");
  deleteStatement.run(req.params.id);

  res.redirect("/");
});

app.get("/log/:id", (req, res) => {
  const statement = db.prepare(
    "SELECT logs.*, users.username FROM logs INNER JOIN users ON logs.authorid = users.id WHERE logs.id = ?"
  );
  const log = statement.get(req.params.id);

  if (!log) {
    return res.redirect("/");
  }

  const isAuthor = req.user && log.authorid === req.user.userid;

  const sublogsStatement = db.prepare(
    "SELECT sublogs.*, users.username FROM sublogs INNER JOIN users ON sublogs.authorid = users.id WHERE sublogs.logid = ? ORDER BY sublogs.createdDate ASC"
  );
  const sublogs = sublogsStatement.all(req.params.id);

  res.render("single-log", { log, isAuthor, sublogs });
});

app.post("/create-log", mustBeLoggedIn, (req, res) => {
  const errors = sharedLogValidation(req);

  if (errors.length) {
    return res.render("create-log", { errors });
  }

  // save into database
  const insertStatement = db.prepare(
    "INSERT INTO logs (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)"
  );
  const result = insertStatement.run(
    req.body.title,
    req.body.body,
    req.user.userid,
    new Date().toISOString()
  );

  const getLogStatement = db.prepare("SELECT * FROM logs WHERE ROWID = ?");
  const realLog = getLogStatement.get(result.lastInsertRowid);

  res.redirect(`/log/${realLog.id}`);
});

app.post("/create-sublog/:logid", mustBeLoggedIn, (req, res) => {
  const errors = [];

  if (typeof req.body.body !== "string") req.body.body = "";

  req.body.body = sanitizeHTML(req.body.body.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  if (!req.body.body) errors.push("You must provide content for the sublog.");

  if (errors.length) {
    return res.redirect(`/log/${req.params.logid}`);
  }

  // save into database
  const insertStatement = db.prepare(
    "INSERT INTO sublogs (body, authorid, logid, createdDate) VALUES (?, ?, ?, ?)"
  );
  insertStatement.run(
    req.body.body,
    req.user.userid,
    req.params.logid,
    new Date().toISOString()
  );

  res.redirect(`/log/${req.params.logid}`);
});

app.post("/register", (req, res) => {
  const errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim();

  if (!req.body.username) errors.push("You must provide a username.");
  if (req.body.username && req.body.username.length < 3)
    errors.push("Username must be at least 3 characters.");
  if (req.body.username && req.body.username.length > 10)
    errors.push("Username cannot exceed 10 characters.");
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain letters and numbers.");

  // check if username exists already
  const usernameStatement = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  );
  const usernameCheck = usernameStatement.get(req.body.username);

  if (usernameCheck) errors.push("That username is already taken.");

  if (!req.body.password) errors.push("You must provide a password.");
  if (req.body.password && req.body.password.length < 12)
    errors.push("Password must be at least 12 characters.");
  if (req.body.password && req.body.password.length > 70)
    errors.push("Password cannot exceed 70 characters.");

  if (errors.length) {
    return res.render("homepage", { errors });
  }

  // save the new user into a database
  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);

  const insertStatement = db.prepare(
    "INSERT INTO users (username, password) VALUES (?, ?)"
  );
  const result = insertStatement.run(req.body.username, req.body.password);

  const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?");
  const newUser = lookupStatement.get(result.lastInsertRowid);

  // log the user in by giving them a cookie
  const authToken = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skyColor: "blue",
      userid: newUser.id,
      username: newUser.username,
    },
    process.env.JWTSECRET
  );

  res.cookie("devlogAuthToken", authToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  res.redirect("/");
});

app.listen(3000);
