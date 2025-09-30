import express from 'express';
import dotenv from 'dotenv';
import axios from 'axios';

dotenv.config();

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

const {
    SSO_CLIENT_ID,
    SSO_CLIENT_SECRET,
    SSO_SERVER_URL,
    CLIENT_CALLBACK_URL,
    PORT
} = process.env;

// "Banco de dados" em memória para simplificar
let tokens = {};

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/login', (req, res) => {
    const authorizeUrl = new URL('/oauth/authorize', SSO_SERVER_URL);
    authorizeUrl.searchParams.append('response_type', 'code');
    authorizeUrl.searchParams.append('client_id', SSO_CLIENT_ID);
    authorizeUrl.searchParams.append('redirect_uri', CLIENT_CALLBACK_URL);
    
    // --- LINHA ADICIONADA ---
    // Pedimos as permissões 'openid', 'profile', e 'email', separadas por espaços.
    authorizeUrl.searchParams.append('scope', 'openid profile email');
    // -------------------------

    authorizeUrl.searchParams.append('state', 'random_string_for_security'); 

    res.redirect(authorizeUrl.toString());
});

app.get('/callback', async (req, res) => {
    const { code } = req.query;

    if (!code) {
        return res.status(400).send('Erro: Código de autorização não encontrado.');
    }

    try {
        const tokenResponse = await axios.post(`${SSO_SERVER_URL}/oauth/token`, new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: CLIENT_CALLBACK_URL,
            client_id: SSO_CLIENT_ID,
            client_secret: SSO_CLIENT_SECRET
        }), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        tokens.access_token = tokenResponse.data.access_token;
        tokens.refresh_token = tokenResponse.data.refresh_token;

        const userResponse = await axios.get(`${SSO_SERVER_URL}/oauth/userinfo`, {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            }
        });
        
        res.render('profile', { user: userResponse.data, tokenData: tokens });

    } catch (error) {
        console.error('Erro no fluxo OAuth:', error.response ? error.response.data : error.message);
        res.status(500).send('Ocorreu um erro durante a autenticação.');
    }
});

app.post('/refresh', async (req, res) => {
    if (!tokens.refresh_token) {
        return res.status(400).send('Nenhum refresh token disponível. Faça login novamente.');
    }
    
    try {
        const refreshTokenResponse = await axios.post(`${SSO_SERVER_URL}/oauth/token`, new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: tokens.refresh_token,
            client_id: SSO_CLIENT_ID,
            client_secret: SSO_CLIENT_SECRET
        }));

        tokens.access_token = refreshTokenResponse.data.access_token;
        tokens.refresh_token = refreshTokenResponse.data.refresh_token;

        const userResponse = await axios.get(`${SSO_SERVER_URL}/oauth/userinfo`, {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`
            }
        });

        res.render('profile', { user: userResponse.data, tokenData: tokens });
        
    } catch (error) {
        console.error('Erro ao refrescar o token:', error.response ? error.response.data : error.message);
        res.status(500).send('Não foi possível renovar sua sessão. Por favor, faça login novamente.');
    }
});


app.listen(PORT, () => {
    console.log(`🚀 Aplicação Cliente de Teste rodando na porta ${PORT}`);
    console.log(`Acesse http://localhost:${PORT} para iniciar.`);
});