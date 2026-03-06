<?php
declare(strict_types=1);

session_start();

/*
 * A coluna `usuarios.senha` foi definida como VARCHAR(20).
 * Isso impede o uso de hashes modernos como password_hash().
 * Esta pagina grava a senha exatamente como recebida para permanecer
 * compativel com o schema atual. O ideal e migrar a coluna para
 * VARCHAR(255) e atualizar o fluxo para usar password_hash().
 */

$dbConfig = [
    'host' => getenv('LIMOBI_DB_HOST') ?: 'localhost',
    'name' => getenv('LIMOBI_DB_NAME') ?: 'lucianoi_dbCentral',
    'user' => getenv('LIMOBI_DB_USER') ?: 'seu_usuario',
    'pass' => getenv('LIMOBI_DB_PASS') ?: 'sua_senha',
    'charset' => 'utf8',
];

$initialValues = [
    'idEmpresa' => '',
    'nomeUsuario' => '',
    'senha' => '',
    'nomePessoa' => '',
    'email' => '',
    'telefone' => '',
    'cargo' => '',
    'funcao' => '',
    'permissao' => '',
];

$values = $initialValues;
$errors = [];
$successMessage = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['csrf_token'];

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function value(array $values, string $key): string
{
    return escape($values[$key] ?? '');
}

function validateMaxLength(string $field, string $value, int $length, array &$errors): void
{
    if (mb_strlen($value) > $length) {
        $errors[] = sprintf('%s deve ter no maximo %d caracteres.', $field, $length);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    foreach ($initialValues as $field => $defaultValue) {
        $values[$field] = trim((string)($_POST[$field] ?? $defaultValue));
    }

    $submittedToken = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($csrfToken, $submittedToken)) {
        $errors[] = 'Sessao expirada. Recarregue a pagina e tente novamente.';
    }

    if ($values['idEmpresa'] === '' || filter_var($values['idEmpresa'], FILTER_VALIDATE_INT) === false) {
        $errors[] = 'Informe um idEmpresa valido.';
    }

    if ($values['nomeUsuario'] === '') {
        $errors[] = 'Informe o nome de usuario.';
    }

    if ($values['senha'] === '') {
        $errors[] = 'Informe a senha.';
    }

    if ($values['nomePessoa'] === '') {
        $errors[] = 'Informe o nome da pessoa.';
    }

    if ($values['email'] === '' || filter_var($values['email'], FILTER_VALIDATE_EMAIL) === false) {
        $errors[] = 'Informe um e-mail valido.';
    }

    if ($values['telefone'] === '') {
        $errors[] = 'Informe o telefone.';
    }

    if ($values['cargo'] === '') {
        $errors[] = 'Informe o cargo.';
    }

    if ($values['funcao'] === '') {
        $errors[] = 'Informe a funcao.';
    }

    if ($values['permissao'] === '' || filter_var($values['permissao'], FILTER_VALIDATE_INT) === false) {
        $errors[] = 'Informe uma permissao valida.';
    }

    validateMaxLength('nomeUsuario', $values['nomeUsuario'], 40, $errors);
    validateMaxLength('senha', $values['senha'], 20, $errors);
    validateMaxLength('nomePessoa', $values['nomePessoa'], 40, $errors);
    validateMaxLength('email', $values['email'], 40, $errors);
    validateMaxLength('telefone', $values['telefone'], 20, $errors);
    validateMaxLength('cargo', $values['cargo'], 20, $errors);
    validateMaxLength('funcao', $values['funcao'], 300, $errors);

    if ($dbConfig['user'] === 'seu_usuario' || $dbConfig['pass'] === 'sua_senha') {
        $errors[] = 'Configure LIMOBI_DB_USER e LIMOBI_DB_PASS antes de usar esta pagina.';
    }

    if (!$errors) {
        try {
            $dsn = sprintf(
                'mysql:host=%s;dbname=%s;charset=%s',
                $dbConfig['host'],
                $dbConfig['name'],
                $dbConfig['charset']
            );

            $pdo = new PDO(
                $dsn,
                $dbConfig['user'],
                $dbConfig['pass'],
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                ]
            );

            $statement = $pdo->prepare(
                'INSERT INTO usuarios (
                    idEmpresa,
                    nomeUsuario,
                    senha,
                    nomePessoa,
                    email,
                    telefone,
                    cargo,
                    funcao,
                    permissao
                ) VALUES (
                    :idEmpresa,
                    :nomeUsuario,
                    :senha,
                    :nomePessoa,
                    :email,
                    :telefone,
                    :cargo,
                    :funcao,
                    :permissao
                )'
            );

            $statement->execute([
                ':idEmpresa' => (int)$values['idEmpresa'],
                ':nomeUsuario' => $values['nomeUsuario'],
                ':senha' => $values['senha'],
                ':nomePessoa' => $values['nomePessoa'],
                ':email' => $values['email'],
                ':telefone' => $values['telefone'],
                ':cargo' => $values['cargo'],
                ':funcao' => $values['funcao'],
                ':permissao' => (int)$values['permissao'],
            ]);

            $successMessage = 'Usuario cadastrado com sucesso.';
            $values = $initialValues;
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $csrfToken = $_SESSION['csrf_token'];
        } catch (PDOException $exception) {
            $errors[] = 'Nao foi possivel cadastrar o usuario. Verifique a conexao com o banco e a existencia da tabela `usuarios`.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Limobi | Criar usuario</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --sand: #f7efe2;
            --linen: #f1e6d5;
            --mist: #ddeae6;
            --lagoon: #5b8d85;
            --pine: #23423d;
            --pine-soft: #496c64;
            --ink: #21322f;
            --muted: #667a75;
            --white: #ffffff;
            --danger-bg: #fff0eb;
            --danger-text: #8f4334;
            --success-bg: #eef8f2;
            --success-text: #2d694a;
            --shadow: 0 24px 60px rgba(35, 66, 61, 0.14);
            --shadow-soft: 0 12px 28px rgba(35, 66, 61, 0.09);
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;
        }

        body {
            font-family: "Plus Jakarta Sans", sans-serif;
            color: var(--ink);
            background:
                radial-gradient(circle at top left, rgba(255, 255, 255, 0.82), transparent 28%),
                linear-gradient(135deg, #f8f0e2 0%, #eef6f3 46%, #dfece7 100%);
        }

        .page {
            min-height: 100vh;
            padding: 28px;
        }

        .brand {
            display: inline-flex;
            align-items: center;
            color: var(--pine);
            text-decoration: none;
            font-family: "Cormorant Garamond", serif;
            font-size: clamp(2rem, 3vw, 2.8rem);
            font-weight: 700;
            letter-spacing: 0.02em;
        }

        .layout {
            display: grid;
            grid-template-columns: 0.95fr 1.05fr;
            gap: 28px;
            margin-top: 22px;
        }

        .hero,
        .card {
            border-radius: 30px;
            background: rgba(255, 255, 255, 0.72);
            border: 1px solid rgba(255, 255, 255, 0.7);
            backdrop-filter: blur(14px);
            box-shadow: var(--shadow);
        }

        .hero {
            padding: 38px;
            background:
                linear-gradient(180deg, rgba(255, 255, 255, 0.68), rgba(255, 255, 255, 0.44)),
                linear-gradient(135deg, rgba(247, 239, 226, 0.94), rgba(221, 234, 230, 0.9));
        }

        .eyebrow {
            margin: 0 0 14px;
            color: var(--pine-soft);
            font-size: 0.76rem;
            font-weight: 700;
            letter-spacing: 0.18em;
            text-transform: uppercase;
        }

        .hero h1 {
            margin: 0;
            max-width: 12ch;
            font-family: "Cormorant Garamond", serif;
            font-size: clamp(3rem, 5vw, 5rem);
            line-height: 0.92;
            color: var(--pine);
        }

        .hero p {
            margin: 18px 0 0;
            max-width: 52ch;
            color: var(--muted);
            line-height: 1.75;
        }

        .chip-group {
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            margin-top: 28px;
        }

        .chip {
            padding: 14px 16px;
            border-radius: 18px;
            background: rgba(255, 255, 255, 0.78);
            box-shadow: var(--shadow-soft);
        }

        .chip strong {
            display: block;
            color: var(--pine);
            font-size: 1rem;
        }

        .chip span {
            display: block;
            margin-top: 6px;
            color: var(--muted);
            font-size: 0.9rem;
        }

        .hero-note {
            margin-top: 28px;
            padding: 18px 20px;
            border-radius: 20px;
            background: rgba(255, 255, 255, 0.76);
            box-shadow: var(--shadow-soft);
            color: var(--pine);
            line-height: 1.7;
        }

        .card {
            padding: 34px;
        }

        .card h2 {
            margin: 0;
            font-family: "Cormorant Garamond", serif;
            font-size: clamp(2.2rem, 4vw, 3rem);
            line-height: 0.98;
            color: var(--pine);
        }

        .card-copy {
            margin: 10px 0 0;
            color: var(--muted);
            line-height: 1.7;
        }

        .feedback {
            margin-top: 22px;
            padding: 16px 18px;
            border-radius: 18px;
            line-height: 1.65;
        }

        .feedback.error {
            background: var(--danger-bg);
            color: var(--danger-text);
        }

        .feedback.success {
            background: var(--success-bg);
            color: var(--success-text);
        }

        .feedback ul {
            margin: 0;
            padding-left: 20px;
        }

        form {
            display: grid;
            gap: 16px;
            margin-top: 24px;
        }

        .field-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }

        .field {
            display: grid;
            gap: 8px;
        }

        label {
            color: var(--pine);
            font-size: 0.92rem;
            font-weight: 600;
        }

        input,
        textarea,
        select {
            width: 100%;
            padding: 15px 16px;
            border: 1px solid rgba(91, 141, 133, 0.18);
            border-radius: 16px;
            background: #fffcf8;
            color: var(--ink);
            font: inherit;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }

        textarea {
            min-height: 120px;
            resize: vertical;
        }

        input:focus,
        textarea:focus,
        select:focus {
            outline: none;
            border-color: rgba(91, 141, 133, 0.72);
            box-shadow: 0 0 0 4px rgba(91, 141, 133, 0.14);
        }

        .hint {
            color: var(--muted);
            font-size: 0.84rem;
            line-height: 1.6;
        }

        .submit-button {
            border: 0;
            border-radius: 18px;
            padding: 16px 20px;
            background: linear-gradient(135deg, var(--pine) 0%, var(--lagoon) 100%);
            color: var(--white);
            font: inherit;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 18px 30px rgba(91, 141, 133, 0.28);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .submit-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 20px 36px rgba(91, 141, 133, 0.32);
        }

        @media (max-width: 1080px) {
            .layout {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 760px) {
            .page {
                padding: 18px;
            }

            .hero,
            .card {
                padding: 24px;
            }

            .field-row {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="page">
        <a class="brand" href="./index.html">Limobi</a>

        <main class="layout">
            <section class="hero">
                <p class="eyebrow">Cadastro de usuarios</p>
                <h1>Organize acesso, equipe e operacao em um unico fluxo.</h1>
                <p>
                    Esta pagina cria novos usuarios diretamente na tabela <strong>usuarios</strong>,
                    mantendo o cadastro centralizado para operacoes de atendimento, reservas e servicos.
                </p>

                <div class="chip-group">
                    <div class="chip">
                        <strong>Cadastro claro</strong>
                        <span>Campos alinhados ao schema do banco.</span>
                    </div>
                    <div class="chip">
                        <strong>Fluxo direto</strong>
                        <span>Insercao preparada com PDO e placeholders.</span>
                    </div>
                    <div class="chip">
                        <strong>Validacao simples</strong>
                        <span>Checagem de tamanho, obrigatoriedade e formato.</span>
                    </div>
                </div>

                <div class="hero-note">
                    O banco informado no schema e <strong>lucianoi_dbCentral</strong>. A pagina usa por
                    padrao as variaveis de ambiente <code>LIMOBI_DB_HOST</code>, <code>LIMOBI_DB_NAME</code>,
                    <code>LIMOBI_DB_USER</code> e <code>LIMOBI_DB_PASS</code>.
                </div>
            </section>

            <section class="card">
                <h2>Criar usuario</h2>
                <p class="card-copy">
                    Preencha os dados abaixo para inserir um novo registro na tabela <strong>usuarios</strong>.
                </p>

                <?php if ($errors): ?>
                    <div class="feedback error">
                        <ul>
                            <?php foreach ($errors as $error): ?>
                                <li><?= escape($error) ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>

                <?php if ($successMessage !== ''): ?>
                    <div class="feedback success">
                        <?= escape($successMessage) ?>
                    </div>
                <?php endif; ?>

                <form method="post" action="">
                    <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">

                    <div class="field-row">
                        <div class="field">
                            <label for="idEmpresa">ID da empresa</label>
                            <input id="idEmpresa" name="idEmpresa" type="number" min="1" value="<?= value($values, 'idEmpresa') ?>" required>
                        </div>

                        <div class="field">
                            <label for="permissao">Permissao</label>
                            <input id="permissao" name="permissao" type="number" min="0" value="<?= value($values, 'permissao') ?>" required>
                        </div>
                    </div>

                    <div class="field-row">
                        <div class="field">
                            <label for="nomeUsuario">Nome de usuario</label>
                            <input id="nomeUsuario" name="nomeUsuario" type="text" maxlength="40" value="<?= value($values, 'nomeUsuario') ?>" required>
                        </div>

                        <div class="field">
                            <label for="senha">Senha</label>
                            <input id="senha" name="senha" type="text" maxlength="20" value="<?= value($values, 'senha') ?>" required>
                            <div class="hint">Compatibilidade atual com o campo `senha VARCHAR(20)`.</div>
                        </div>
                    </div>

                    <div class="field-row">
                        <div class="field">
                            <label for="nomePessoa">Nome da pessoa</label>
                            <input id="nomePessoa" name="nomePessoa" type="text" maxlength="40" value="<?= value($values, 'nomePessoa') ?>" required>
                        </div>

                        <div class="field">
                            <label for="email">E-mail</label>
                            <input id="email" name="email" type="email" maxlength="40" value="<?= value($values, 'email') ?>" required>
                        </div>
                    </div>

                    <div class="field-row">
                        <div class="field">
                            <label for="telefone">Telefone</label>
                            <input id="telefone" name="telefone" type="text" maxlength="20" value="<?= value($values, 'telefone') ?>" required>
                        </div>

                        <div class="field">
                            <label for="cargo">Cargo</label>
                            <input id="cargo" name="cargo" type="text" maxlength="20" value="<?= value($values, 'cargo') ?>" required>
                        </div>
                    </div>

                    <div class="field">
                        <label for="funcao">Funcao</label>
                        <textarea id="funcao" name="funcao" maxlength="300" required><?= value($values, 'funcao') ?></textarea>
                    </div>

                    <button class="submit-button" type="submit">Cadastrar usuario</button>
                </form>
            </section>
        </main>
    </div>
</body>
</html>
