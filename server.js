const express = require("express");
const fs = require("fs");
const path = require("path");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const SECRET_KEY = "minha_chave_secreta";

app.use(bodyParser.json());

const usersFilePath = path.join(__dirname, "users.json");

// Caminho para o arquivo de contas
const accountsFilePath = path.join(__dirname, "accounts.json");

// Rota: Get Account by userId
app.get("/accounts/:userId", authenticateToken, (req, res) => {
  try {
    const userId = req.params.userId;

    // Lendo dados do arquivo
    const data = JSON.parse(fs.readFileSync(accountsFilePath, "utf-8"));
    const accounts = data.accounts;

    // Encontrando conta pelo userId
    const account = accounts.find(acc => acc.userId === userId);

    if (!account) {
      return res.status(404).json({ error: "Conta não encontrada" });
    }

    res.json(account);
  } catch (error) {
    console.error("Erro ao buscar conta:", error);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
});


// Lista de tokens inválidos (simulação de logout)
let invalidTokens = [];

// Middleware para autenticar JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token não fornecido" });
  if (invalidTokens.includes(token)) {
    return res.status(401).json({ error: "Token expirado ou inválido" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user;
    req.token = token;
    next();
  });
}

// Criar ou atualizar senha de transferência
app.post("/accounts/set_transfer_password", authenticateToken, (req, res) => {
  try {
    const { accountNumber, transfer_password } = req.body;

    if (!accountNumber || !transfer_password || !/^\d{4,}$/.test(transfer_password)) {
      return res.status(400).json({
        error: "Dados inválidos. A senha deve ter no mínimo 4 dígitos numéricos."
      });
    }

    const data = JSON.parse(fs.readFileSync(accountsFilePath, "utf-8"));
    const accounts = data.accounts;

    const account = accounts.find(acc => acc.accountNumber === accountNumber);

    if (!account) return res.status(404).json({ error: "Conta não encontrada" });
    if (account.userId !== req.user.id)
      return res.status(403).json({ error: "Acesso negado a esta conta" });

    res.status(200).json({ message: "Senha de transferência definida/atualizada com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
});

// Trocar senha de transferência
app.post("/accounts/change_transfer_password", authenticateToken, (req, res) => {
  try {
    const { accountNumber, old_transfer_password, new_transfer_password } = req.body;

    if (!accountNumber || !old_transfer_password || !new_transfer_password || !/^\d{4,}$/.test(new_transfer_password)) {
      return res.status(400).json({
        error: "Dados inválidos. Informe senha antiga e nova senha com no mínimo 4 dígitos numéricos."
      });
    }

    const data = JSON.parse(fs.readFileSync(accountsFilePath, "utf-8"));
    const accounts = data.accounts;

    const account = accounts.find(acc => acc.accountNumber === accountNumber);

    if (!account) return res.status(404).json({ error: "Conta não encontrada" });
    if (account.userId !== req.user.id)
      return res.status(403).json({ error: "Acesso negado a esta conta" });

    // Precisa já ter senha cadastrada
    if (!account.transfer_password) {
      return res.status(400).json({ error: "Ainda não existe senha de transferência definida." });
    }

    // Valida a senha antiga
    if (account.transfer_password !== old_transfer_password) {
      return res.status(401).json({ error: "Senha atual incorreta." });
    }

    if (account.transfer_password == new_transfer_password) {
      return res.status(401).json({ error: "A nova senha não pode ser igual a atual." });
    }

    // Atualiza com a nova senha
    account.transfer_password = new_transfer_password;
    fs.writeFileSync(accountsFilePath, JSON.stringify({ accounts }, null, 2));

    res.status(200).json({ message: "Senha de transferência alterada com sucesso." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
});

// Verificar senha de transferência
app.post("/accounts/verify_transfer_password", authenticateToken, (req, res) => {
  try {
    const { accountNumber, transfer_password } = req.body;

    const data = JSON.parse(fs.readFileSync(accountsFilePath, "utf-8"));
    const accounts = data.accounts;

    const account = accounts.find(acc => acc.accountNumber === accountNumber);

    if (!account) return res.status(404).json({ error: "Conta não encontrada" });

    if (account.userId !== req.user.id)
      return res.status(403).json({ error: "Acesso negado a esta conta" });

    if (!account.transfer_password) {
      return res.status(401).json({ code: "P404", error: "Senha de transferência não definida. Por favor, defina-a antes de transferir." });
    }

    res.status(200).json({ message: "Senha de transferência válida" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
});

// Transferência de valores
app.post("/accounts/transfer", authenticateToken, (req, res) => {
  try {
    const { fromAccountNumber, toAccountNumber, transfer_password, amount } = req.body;

    if (!fromAccountNumber || !toAccountNumber || typeof amount !== "number" || isNaN(amount) || !transfer_password) {
      return res.status(400).json({ error: "Dados inválidos" });
    }

    const data = JSON.parse(fs.readFileSync(accountsFilePath, "utf-8"));
    const accounts = data.accounts;

    const fromAccount = accounts.find(acc => acc.accountNumber === fromAccountNumber);
    const toAccount = accounts.find(acc => acc.accountNumber === toAccountNumber);

    if (!fromAccount || !toAccount) {
      return res.status(404).json({ error: "Conta origem ou destino não encontrada" });
    }

    if (fromAccount.id === toAccount.id) {
      return res.status(400).json({ error: "Não é possível transferir para a mesma conta" });
    }

    // Verificação da senha
    if (!fromAccount.transfer_password) {
      return res.status(401).json({ code: "P404", error: "Senha de transferência não definida. Por favor, defina-a antes de transferir." });
    }

    if (fromAccount.transfer_password !== transfer_password) {
      return res.status(401).json({ code: "P401", error: "Senha de transferência incorreta" });
    }

    if (amount <= 0) {
      return res.status(400).json({ error: "O valor deve ser maior que zero" });
    }

    if (fromAccount.balance < amount) {
      return res.status(400).json({ error: "Saldo insuficiente" });
    }

    // Corrigindo imprecisão decimal
    fromAccount.balance = parseFloat((fromAccount.balance - amount).toFixed(2));
    toAccount.balance = parseFloat((toAccount.balance + amount).toFixed(2));

    fs.writeFileSync(accountsFilePath, JSON.stringify({ accounts }, null, 2));

    res.status(200).json({
      message: "Transferência realizada com sucesso",
      fromAccount,
      toAccount,
    });
  } catch (error) {
    console.error("Erro na transferência:", error);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
});

// Rota: Get Balance
app.get("/accounts/:accountId/balance", authenticateToken, (req, res) => {
  try {
    const { accountId } = req.params;

    // Lendo dados do arquivo
    const data = JSON.parse(fs.readFileSync(accountsFilePath, "utf-8"));
    const accounts = data.accounts;

    // Busca a conta pelo id
    const account = accounts.find(acc => acc.id === accountId);

    if (!account) {
      return res.status(404).json({ error: "Conta não encontrada" });
    }

    // Verifica se a conta pertence ao usuário logado
    if (account.userId !== req.user.id) {
      return res.status(403).json({ error: "Acesso negado a esta conta" });
    }

    // Retorna apenas o saldo
    res.status(200).json({ balance: account.balance });
  } catch (error) {
    console.error("Erro ao buscar saldo:", error);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
});



// Rota: Register
app.post("/register", (req, res) => {
  const { username, email, password, } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "Todos os campos são obrigatórios" });
  }

  // Lendo usuários
  const usersData = JSON.parse(fs.readFileSync(usersFilePath, "utf-8"));
  const users = usersData.users;

  if (users.find((u) => u.username === username || u.email === email)) {
    return res.status(400).json({ error: "Usuário ou email já cadastrados" });
  }

  // Criando novo usuário
  const newUser = {
    id: `user${users.length + 1}`,
    username,
    email,
    password
  };

  users.push(newUser);
  fs.writeFileSync(usersFilePath, JSON.stringify({ users }, null, 2));

  // Lendo contas
  const accountsData = JSON.parse(fs.readFileSync(accountsFilePath, "utf-8"));
  const accounts = accountsData.accounts;

  // Criando conta vinculada ao usuário
  const newAccount = {
    id: `acc${accounts.length + 1}`,
    userId: newUser.id,
    accountNumber: `${Math.floor(Math.random() * 90000) + 10000}-${Math.floor(Math.random() * 9)}`,
    balance: 0, // conta começa zerada
  };

  accounts.push(newAccount);
  fs.writeFileSync(accountsFilePath, JSON.stringify({ accounts }, null, 2));

  // Gerando token JWT
  const token = jwt.sign(
    { id: newUser.id, username: newUser.username, email: newUser.email },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.status(201).json({
    message: "Usuário e conta criados com sucesso",
    token,
    user: newUser,
    account: newAccount
  });
});


// Rota: Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Usuário e senha são obrigatórios" });
  }

  const data = JSON.parse(fs.readFileSync(usersFilePath, "utf-8"));
  const users = data.users;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ error: "Credenciais inválidas" });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login realizado com sucesso",
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email
    }
  });

});

// Rota: Logout
app.post("/logout", authenticateToken, (req, res) => {
  invalidTokens.push(req.token);
  res.json({ status: true, message: "Logout realizado com sucesso" });
});

// Rota: Get Current User
app.get("/me", authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});
