  <h2>1️⃣ Criar Ambiente Virtual</h2>
  <pre><code>python3 -m venv venv
source venv/bin/activate</code></pre>

  <hr>

  <h2>2️⃣ Instalar Dependências</h2>
  <pre><code>pip install --upgrade pip
pip install -r requirements.txt</code></pre>

  <hr>

  <h2>3️⃣ Formatar Código com Black</h2>
  <pre><code>black .</code></pre>

  <p>Verificar formatação (mesmo padrão do CI):</p>
  <pre><code>black --check .</code></pre>

  <hr>

  <h2>4️⃣ Fluxo de Desenvolvimento</h2>
  <pre><code>Criar branch
git checkout -b feature/nome-da-feature

# Validar antes do commit

black .
flake8 .
pytest

# Commit e push

git add .
git commit -m "feat: descrição da funcionalidade"
git push origin feature/nome-da-feature</code></pre>

  <p>Abra o Pull Request e aguarde a validação automática do CI.</p>
