//IMPORTS
require("dotenv").config();
var express = require("express");
var mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
var cors = require("cors");

var app = express();

//Configura resposta JSON
app.use(express.json());
//Configura CORS

app.use(cors())

//Models
const User = require("./models/User");

//Rota pública
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Welcome to login API!" });
});

//Rota privada
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  //Checa se o user existe
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "Account not found" });
  }

  return res.status(200).json({ user });
});

//Verifica o token
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "Access denied" });
  }

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (error) {
    res.status(400).json({ msg: "Invalid token" });
  }
}

//Resgistrar Usuario
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  //Validação
  if (!name) {
    return res.status(422).json({ msg: "Name is required" });
  }
  if (!email) {
    return res.status(422).json({ msg: "Email is required" });
  }
  if (!password) {
    return res.status(422).json({ msg: "Password is required" });
  }
  if (password !== confirmpassword) {
    return res.status(422).json({ msg: "Passwords are different" });
  }

  //Veirifica se usuario ja existe
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: "Email already exists" });
  }

  //Cria senha codificada
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  //Cria usuario
  const user = new User({
    name,
    email,
    password: passwordHash,
  });
  //Tenta salvar usuario no banco
  try {
    await user.save();
    res.status(201).json({ msg: "Account has been created" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: "Server error: try later " });
  }
});

//Login Usuario
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //Validação
  if (!email) {
    return res.status(422).json({ msg: "Email is required" });
  }
  if (!password) {
    return res.status(422).json({ msg: "Password is required" });
  } 

  //Checa se o usuario existe
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(422).json({ msg: "Account not found" });
  }

  //Checa se a senha está certa
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Invalid password" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );
    res
      .status(200)
      .json({ msg: "Authentication completed", token, userId: user._id });
  } catch (err) {
    console.log(error);
    res.status(500).json({ msg: "Server error" });
  }
});

// Rota de deleção de usuário
app.delete("/user/:id", checkToken, async (req, res) => {
  const userId = req.params.id;

  try {
    // Verifica se o usuário existe
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    // Deleta o usuário do banco de dados
    await User.findByIdAndDelete(userId);

    return res.status(200).json({ msg: "User deleted successfully" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ msg: "Server error: try later" });
  }
});

// Rota de atualização de usuário
app.put("/user/:id", checkToken, async (req, res) => {
  const userId = req.params.id;
  const { name, email } = req.body;

  try {
    // Verifica se o usuário existe
    const user = await User.findById(userId, "-passowrd");
    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    // Atualiza informações do usuário
    user.name = name || user.name;
    user.email = email || user.email;

    // Salva as alterações no banco de dados
    await user.save();

    return res.status(200).json({ msg: "User updated successfully", user });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ msg: "Server error: try later" });
  }
});

//Credenciais

mongoose
  .connect(process.env.DB_CONNECT)
  .then(() => {
    app.listen(3000)
    console.log("Conected");
  })
  .catch((err) => console.log(err));
