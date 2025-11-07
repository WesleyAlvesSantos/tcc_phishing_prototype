# Variáveis globais
ISOLATION_MODEL = None

# Feature composta: ativa se link encurtado, urgência e domínio suspeito
def alerta_phishing(texto: str, from_domain: str) -> int:
    urgente = detectar_urgencia(texto)
    encurtado = contem_link_encurtado(texto)
    suspeito = dominio_suspeito(from_domain)
    return int(urgente and encurtado and suspeito)
from sklearn.utils import resample
# Detecta se há link encurtado no texto
def contem_link_encurtado(texto: str) -> int:
    if pd.isna(texto):
        return 0
    padroes = [
        r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r'ow\.ly', r'is\.gd', r'cutt\.ly', r'shorte\.st', r'rebrand\.ly', r'lnkd\.in', r't\.co', r'cli\.ck', r'v\.gd', r'buff\.ly', r'adf\.ly'
    ]
    return int(any(re.search(p, texto.lower()) for p in padroes))

# Domínios suspeitos comuns
DOMINIOS_SUSPEITOS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.ru', 'protonmail.com', 'icloud.com', 'gmx.com', 'zoho.com', 'yandex.com', 'bol.com.br', 'uol.com.br', 'terra.com.br', 'live.com', '163.com', 'qq.com', 'rediffmail.com', 'hushmail.com', 'email.com', 'fastmail.com', 'inbox.com', 'mail.com', 'bk.ru', 'list.ru', 'inbox.ru', 'mailinator.com', 'tempmail', '10minutemail', 'guerrillamail', 'trashmail', 'maildrop', 'dispostable', 'fakeinbox', 'getnada', 'yopmail'
]

def dominio_suspeito(dominio: str) -> int:
    if pd.isna(dominio) or dominio == 'desconhecido':
        return 1
    # Verifica se o domínio contém exatamente algum dos itens suspeitos (match por sufixo ou token)
    dominio = dominio.lower()
    for s in DOMINIOS_SUSPEITOS:
        if dominio.endswith(s) or ('.' + s) in ('.' + dominio):
            return 1
    return 0

# Lista de domínios reconhecidamente confiáveis (whitelist) para evitar falsos positivos
DOMINIOS_CONFIAVEIS = [
    # Serviços online
    'epicgames.com', 'accounts.epicgames.com', 'paypal.com', 'google.com', 'microsoft.com',
    'github.com', 'apple.com',
    # Bancos tradicionais
    'itau-unibanco.com.br', 'bradesco.com.br', 'bb.com.br', 'santander.com.br', 'caixa.gov.br',
    # Bancos digitais e instituições financeiras
    'nubank.com.br', 'bancointer.com.br', 'sicoob.com.br', 'btgpactual.com', 'c6bank.com.br',
    'xpi.com.br'
]

def dominio_confiavel(dominio: str) -> bool:
    if pd.isna(dominio) or dominio == 'desconhecido':
        return False
    dominio = dominio.lower()

    # Checa lista fixa (match por sufixo/exato — evita substrings genéricas que geram falsos positivos)
    for s in DOMINIOS_CONFIAVEIS:
        s = s.lower().strip()
        if dominio == s or dominio.endswith('.' + s) or dominio.endswith(s):
            return True

    # Checa whitelist persistente em whitelist.txt
    def load_whitelist_local() -> set:
        fn = 'whitelist.txt'
        if not os.path.exists(fn):
            return set()
        try:
            with open(fn, 'r', encoding='utf-8') as f:
                return set(line.strip().lower() for line in f if line.strip())
        except Exception:
            return set()

    wl = load_whitelist_local()
    for s in wl:
        s = s.lower().strip()
        if dominio == s or dominio.endswith('.' + s) or dominio.endswith(s):
            return True
    return False

def save_whitelist(domain: str):
    """Adiciona um domínio ao arquivo whitelist.txt (uma linha por domínio)."""
    if not domain:
        return
    d = domain.strip().lower()
    fn = os.path.join(os.getcwd(), 'whitelist.txt')
    try:
        existing = set()
        if os.path.exists(fn):
            with open(fn, 'r', encoding='utf-8') as f:
                existing = set(line.strip().lower() for line in f if line.strip())
        if d in existing:
            return
        with open(fn, 'a', encoding='utf-8') as f:
            f.write(d + "\n")
    except Exception:
        pass

# end whitelist helpers
import streamlit as st
import pandas as pd
import numpy as np
import re
import unicodedata
import joblib
import os
import difflib
import json
from urllib.parse import urlparse
try:
    import tld
except Exception:
    tld = None
from email.utils import parseaddr
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

# Modelo de detecção de anomalias (será treinado em treinar_melhor_modelo)
ISOLATION_MODEL = None

# Limiares e pesos configuráveis (podem ser ajustados na UI)
MODEL_THRESHOLD = 0.5
WEIGHTS = {
    'urgency': 0.15,
    'short_link': 0.2,
    'suspect_domain': 0.25,
    'domain_score': 0.15,
    'emocional': 0.1,
    'comandos': 0.1,
    'anomalia': 0.05
}

# Função para calcular a similaridade entre dois textos
def calcular_similaridade(texto1: str, texto2: str) -> float:
    return difflib.SequenceMatcher(None, texto1, texto2).ratio()

# Função para verificar URLs maliciosas conhecidas
def verificar_url_maliciosa(url: str) -> bool:
    try:
        parsed = urlparse(url)
        dominio = parsed.netloc
        # Aqui você poderia integrar com uma API de reputação de domínios
        return False
    except:
        return False

# Análise avançada de domínios
def analisar_dominio(dominio: str) -> dict:
    if pd.isna(dominio) or dominio == "desconhecido":
        return {
            "suspeito": 1,
            "score_suspeitabilidade": 1.0,
            "razao": "Domínio inválido ou desconhecido"
        }
    
    dominio = dominio.lower()
    scores = []
    razoes = []
    
    # 1. Verificar comprimento anormal
    if len(dominio) > 30:
        scores.append(0.7)
        razoes.append("Domínio muito longo")
    
    # 2. Verificar caracteres repetidos
    if re.search(r'([a-zA-Z0-9])\1{3,}', dominio):
        scores.append(0.8)
        razoes.append("Caracteres repetidos")
    
    # 3. Verificar números excessivos
    if len(re.findall(r'\d', dominio)) > 3:
        scores.append(0.6)
        razoes.append("Excesso de números")
    
    # 4. Verificar hífens excessivos
    if dominio.count('-') > 2:
        scores.append(0.5)
        razoes.append("Excesso de hífens")
    
    # 5. Verificar palavras suspeitas
    palavras_suspeitas = ['secure', 'login', 'verify', 'account', 'banking', 'update']
    if any(p in dominio for p in palavras_suspeitas):
        scores.append(0.9)
        razoes.append("Contém palavras suspeitas")
    
    # 6. Verificar TLD suspeito
    tlds_suspeitos = ['.xyz', '.top', '.work', '.casa', '.surf', '.info']
    if any(dominio.endswith(tld) for tld in tlds_suspeitos):
        scores.append(0.7)
        razoes.append("TLD suspeito")
    
    # 7. Verificar similaridade com domínios conhecidos
    dominios_confiaveis = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com']
    for d in dominios_confiaveis:
        if dominio != d and calcular_similaridade(dominio, d) > 0.8:
            scores.append(0.95)
            razoes.append(f"Muito similar a {d}")
    
    if not scores:
        return {"suspeito": 0, "score_suspeitabilidade": 0.0, "razao": "Nenhum indicador suspeito"}
    
    return {
        "suspeito": int(max(scores) > 0.7),
        "score_suspeitabilidade": max(scores),
        "razao": " | ".join(razoes)
    }


# -------------------------
# Extração e análise de URLs
# -------------------------
import ipaddress

def extrair_urls(texto: str) -> list:
    """Extrai todas as URLs encontradas em um texto (http/https e www.)."""
    if pd.isna(texto) or texto.strip() == "":
        return []
    padrao = re.compile(r'http[s]?://[^\s\)\]"\'<>]+|www\.[^\s\)\]"\'<>]+', re.IGNORECASE)
    return padrao.findall(texto)

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'shorte.st', 'rebrand.ly', 'lnkd.in', 't.co',
    'cli.ck', 'v.gd', 'buff.ly', 'adf.ly'
]

def analisar_url(url: str, from_domain: str = None) -> dict:
    """Analisa uma URL e retorna indicadores de suspeita.

    Não faz requisições de rede; usa heurísticas estáticas.
    """
    info = {
        'url': url,
        'domain': '',
        'is_https': False,
        'is_ip': False,
        'uses_basic_auth': False,
        'is_shortener': False,
        'has_at_sign': False,
        'is_punycode': False,
        'suspicious_path': False,
        'port': None,
        'score': 0.0,
        'matches_sender_domain': False,
        'malicious_local_block': False
    }
    try:
        u = url if url.startswith('http') else 'http://' + url
        parsed = urlparse(u)
        host = parsed.netloc.lower()
        info['is_https'] = parsed.scheme == 'https'
        # remove credenciais em netloc
        if '@' in host:
            info['uses_basic_auth'] = True
            host = host.split('@')[-1]
            info['has_at_sign'] = True
        # extrair porta se presente
        if ':' in host:
            hparts = host.split(':')
            host = hparts[0]
            try:
                info['port'] = int(hparts[1])
            except Exception:
                info['port'] = None
        info['domain'] = host

        # is IP
        try:
            ipaddress.ip_address(host)
            info['is_ip'] = True
        except Exception:
            info['is_ip'] = False

        # shortener
        info['is_shortener'] = any(s in host for s in SHORTENERS)

        # punycode check
        if host.startswith('xn--') or 'xn--' in host:
            info['is_punycode'] = True

        # suspicious path patterns
        path = parsed.path or ''
        if re.search(r'(secure|verify|account|signin|login|confirm|update|bank|password)', path, re.IGNORECASE):
            info['suspicious_path'] = True

        # basic heuristics score
        score = 0.0
        if info['is_ip']:
            score += 0.6
        if info['uses_basic_auth']:
            score += 0.6
        if info['is_shortener']:
            score += 0.5
        if info['is_punycode']:
            score += 0.7
        if info['suspicious_path']:
            score += 0.4
        if not info['is_https']:
            score += 0.1
        if info['port'] not in (None, 80, 443):
            score += 0.2

        # compare with sender domain
        if from_domain:
            try:
                info['matches_sender_domain'] = host.endswith(from_domain)
                if not info['matches_sender_domain']:
                    # small score if domain differs and path is suspicious
                    if info['suspicious_path']:
                        score += 0.2
            except Exception:
                pass

        # local malicious blocklist (optional file)
        mal_path = os.path.join(os.getcwd(), 'maliciosos.txt')
        if os.path.exists(mal_path):
            try:
                with open(mal_path, 'r', encoding='utf-8') as f:
                    blocked = set(l.strip().lower() for l in f if l.strip())
                if host in blocked:
                    info['malicious_local_block'] = True
                    score += 1.0
            except Exception:
                pass

        info['score'] = min(1.0, score)
    except Exception:
        pass
    return info


# Features linguísticas avançadas
def analisar_linguagem(texto: str) -> dict:
    if pd.isna(texto):
        return {
            "erros_gramaticais": 0,
            "formalidade": 0,
            "emocional": 0,
            "comandos": 0
        }
    
    texto = texto.lower()
    
    # Indicadores de erros comuns
    erros_comuns = [
        r'[\w\s]bankk\w*', r'[\w\s]pak\w*', r'[\w\s]mony\w*',
        r'[\w\s]urgent\w*', r'[\w\s]importent\w*'
    ]
    
    # Marcadores de formalidade
    formal = [
        'cordialmente', 'atenciosamente', 'prezado', 'senhor', 'senhora',
        'conforme', 'solicito', 'informo'
    ]
    
    # Marcadores emocionais/urgência
    emocional = [
        'urgente', 'importante', 'imediato', 'crucial', 'vital',
        'risco', 'perigo', 'alerta', 'atenção', 'cuidado'
    ]
    
    # Verbos de comando
    comandos = [
        'clique', 'acesse', 'faça', 'digite', 'confirme', 'verifique',
        'atualize', 'baixe', 'instale', 'envie'
    ]
    
    return {
        "erros_gramaticais": sum(bool(re.search(padrao, texto)) for padrao in erros_comuns),
        "formalidade": sum(palavra in texto for palavra in formal) / len(texto.split()),
        "emocional": sum(palavra in texto for palavra in emocional) / len(texto.split()),
        "comandos": sum(palavra in texto for palavra in comandos) / len(texto.split())
    }

# Detecção de anomalias no texto
def detectar_anomalias_texto(texto: str, modelo_isolation_forest=None) -> float:
    """Detecta se um texto é uma anomalia usando um IsolationForest já treinado.

    Retorna 1 se considerado anômalo (outlier), 0 caso contrário.
    Se o modelo ainda não estiver treinado, retorna 0 (sem anomalia).
    """
    # Extrai as mesmas features usadas para treinar o IsolationForest
    features = [
        len(texto),
        len(re.findall(r'[A-Z]', texto)) / (len(texto) + 1),
        len(re.findall(r'[!?]', texto)) / (len(texto) + 1),
        len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', texto)),
        len(re.findall(r'\d+', texto)) / (len(texto) + 1)
    ]

    # Usa o modelo global se disponível
    try:
        global ISOLATION_MODEL
    except NameError:
        ISOLATION_MODEL = None

    if ISOLATION_MODEL is None:
        # Modelo não treinado ainda -> trata como não anômalo
        return 0

    pred = ISOLATION_MODEL.predict([features])[0]
    # IsolationForest retorna -1 para outliers
    return 1 if int(pred) == -1 else 0

# Detecta se há link encurtado no texto
def contem_link_encurtado(texto: str) -> int:
    if pd.isna(texto):
        return 0
    padroes = [
        r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r'ow\.ly', r'is\.gd', r'cutt\.ly', r'shorte\.st', r'rebrand\.ly', r'lnkd\.in', r't\.co', r'cli\.ck', r'v\.gd', r'buff\.ly', r'adf\.ly'
    ]
    return int(any(re.search(p, texto.lower()) for p in padroes))

# Domínios suspeitos comuns
DOMINIOS_SUSPEITOS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.ru', 'protonmail.com', 'icloud.com', 'gmx.com', 'zoho.com', 'yandex.com', 'bol.com.br', 'uol.com.br', 'terra.com.br', 'live.com', '163.com', 'qq.com', 'rediffmail.com', 'hushmail.com', 'email.com', 'fastmail.com', 'inbox.com', 'mail.com', 'bk.ru', 'list.ru', 'inbox.ru', 'mailinator.com', 'tempmail', '10minutemail', 'guerrillamail', 'trashmail', 'maildrop', 'dispostable', 'fakeinbox', 'getnada', 'yopmail'
]

def dominio_suspeito(dominio: str) -> int:
    if pd.isna(dominio) or dominio == 'desconhecido':
        return 1
    return int(any(s in dominio for s in DOMINIOS_SUSPEITOS))

# Feature composta: ativa se link encurtado, urgência e domínio suspeito
def alerta_phishing(texto: str, from_domain: str) -> int:
    """Ativa um alerta forte quando houver: termo de urgência + link encurtado + domínio suspeito.
    Não ativa se o domínio for confiável (whitelist)."""
    urgente = detectar_urgencia(texto)
    encurtado = contem_link_encurtado(texto)
    suspeito = dominio_suspeito(from_domain)
    if dominio_confiavel(from_domain):
        return 0
    return int(urgente and encurtado and suspeito)
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

# =========================
# Funções de pré-processamento
# =========================

def remover_acentos(texto: str) -> str:
    nfkd = unicodedata.normalize('NFKD', texto)
    return ''.join([c for c in nfkd if not unicodedata.combining(c)])

def limpar_texto(texto: str) -> str:
    if pd.isna(texto):
        return ""
    texto = re.sub(r'<.*?>', ' ', texto)                                  # HTML
    texto = re.sub(r'http\S+|www\.\S+', ' url ', texto)                   # URLs
    texto = re.sub(r'\S+@\S+', ' emailaddr ', texto)                      # e-mails
    texto = re.sub(r'[^a-zA-ZÁ-Úá-ú0-9\s]', ' ', texto)                   # símbolos
    texto = texto.lower()
    texto = remover_acentos(texto)

    stopwords_simples = {
        'de','da','do','das','dos','a','o','as','os','e','em','no','na','nas','nos',
        'para','por','com','sem','um','uma','uns','umas','ao','aos','que','se',
        'sua','seu','suas','seus','the','and','or','to','of','in','on'
    }
    tokens = [t for t in texto.split() if t not in stopwords_simples]
    return ' '.join(tokens)

def contar_urls(texto: str) -> int:
    if pd.isna(texto):
        return 0
    return len(re.findall(r'http\S+|www\.\S+', texto))

def contar_palavras_maiusculas(texto: str) -> int:
    if pd.isna(texto):
        return 0
    tokens = re.findall(r'\b\w+\b', texto)
    return sum(1 for t in tokens if t.isupper() and len(t) > 1)

# Novas features
def comprimento_texto(texto: str) -> int:
    if pd.isna(texto):
        return 0
    return len(texto)

def contar_caracteres_especiais(texto: str) -> int:
    if pd.isna(texto):
        return 0
    return len(re.findall(r'[^\w\s]', texto))

def frequencia_palavras_suspeitas(texto: str) -> int:
    if pd.isna(texto):
        return 0
    palavras = [
        # Português
        'senha', 'banco', 'atualize', 'atualizacao', 'verifique', 'urgente',
        'bloqueio', 'bloqueada', 'confirmar', 'dados', 'conta', 'premio', 'ganhou',
        'imediatamente', 'imediato', 'bloqueio', 'bloqueada', 'bloqueado',
        'seguranca', 'acesso', 'restrito', 'pagamento', 'cartao', 'credito',
        'debito', 'vencimento', 'expiracao', 'codigo', 'validacao', 'reembolso',
        'dinheiro', 'resgate', 'promocao', 'oferta', 'exclusivo', 'limite',
        'desativada', 'desativado', 'problema', 'irregular', 'suspeita',
        'confirmacao', 'validar', 'autenticar', 'autenticacao',
        # English
        'password', 'account', 'update', 'verify', 'urgent', 'blocked', 'winner', 'prize',
        'immediately', 'block', 'blocked', 'suspend', 'suspended',
        'security', 'access', 'restricted', 'payment', 'credit', 'card',
        'debit', 'expiration', 'expires', 'validation', 'code', 'refund',
        'money', 'cash', 'reward', 'promotion', 'offer', 'exclusive', 'limit',
        'deactivated', 'disabled', 'issue', 'irregular', 'suspicious',
        'confirm', 'authenticate', 'validation', 'verify', 'login',
        # Variações comuns
        'confirme', 'verificar', 'verificacao', 'atualizar', 'atualize-se',
        'bloquear', 'desbloquear', 'reativar', 'reative', 'valide',
        'authenticate', 'login', 'sign-in', 'signin', 'log-in',
        'verify-now', 'act-now', 'limited-time', 'tempo-limitado'
    ]
    texto_lower = texto.lower()
    return sum(texto_lower.count(p) for p in palavras)

def detectar_urgencia(texto: str) -> int:
    if pd.isna(texto):
        return 0
    txt = texto.lower()
    termos = [
        'urgente','bloqueio','bloqueada','verifique','verificacao',
        'imediato','imediatamente','senha expirada','confirmar dados',
        'sua conta sera encerrada','urgent','blocked','verify'
    ]
    return int(any(t in txt for t in termos))

def extrair_dominio(remetente: str) -> str:
    """Extrai o domínio do campo remetente de forma robusta.

    Aceita formatos como:
    - nome <email@dominio.com>
    - email@dominio.com
    - apenas 'desconhecido' / vazios
    """
    if pd.isna(remetente) or str(remetente).strip() == "":
        return 'desconhecido'
    try:
        name, email = parseaddr(remetente)
        if not email:
            return 'desconhecido'
        parts = email.split('@')
        if len(parts) != 2:
            return 'desconhecido'
        dominio = parts[1].lower().strip()
        # remove qualquer caractere residual como '>'
        dominio = re.sub(r'[^a-z0-9.\-]', '', dominio)
        return dominio
    except Exception:
        return 'desconhecido'

def parse_remetente(remetente: str) -> dict:
    """Retorna informações extraídas do campo remetente: display_name, email, local_part, domain."""
    if pd.isna(remetente) or str(remetente).strip() == "":
        return {'display_name': '', 'email': '', 'local': '', 'domain': 'desconhecido'}
    try:
        name, email = parseaddr(remetente)
        name = name.strip() if name else ''
        email = email.strip().lower() if email else ''
        if '@' in email:
            local, domain = email.split('@', 1)
            domain = re.sub(r'[^a-z0-9.\-]', '', domain)
        else:
            local, domain = '', 'desconhecido'
        return {'display_name': name, 'email': email, 'local': local, 'domain': domain}
    except Exception:
        return {'display_name': '', 'email': '', 'local': '', 'domain': 'desconhecido'}

def sender_spoof_score(display_name: str, local: str, domain: str) -> float:
    """Calcula um score simples indicando possível spoofing entre display name e domínio/local.

    Score entre 0 e 1 (quanto maior, mais suspeito).
    """
    score = 0.0
    name = (display_name or '').lower()
    local = (local or '').lower()
    domain = (domain or '').lower()

    # se display name contém um brand conhecido mas domain não corresponde -> suspeita
    marcas = ['paypal', 'google', 'microsoft', 'apple', 'epic', 'bank', 'nordea', 'itau', 'bb', 'bancodobrasil']
    for m in marcas:
        if m in name and m not in domain:
            score += 0.5

    # local-part com palavras suspeitas
    suspeitos_local = ['secure', 'support', 'no-reply', 'noreply', 'verify', 'alert']
    if any(s in local for s in suspeitos_local) and not any(s in domain for s in suspeitos_local):
        score += 0.2

    # local muito numérico ou com muitos caracteres especiais
    if len(re.findall(r'\d', local)) > 3:
        score += 0.1
    if local.count('.') > 2 or local.count('-') > 2:
        score += 0.1

    return min(1.0, score)

def subject_exclaim_count(subject: str) -> int:
    if pd.isna(subject):
        return 0
    return subject.count('!')

def subject_question_count(subject: str) -> int:
    if pd.isna(subject):
        return 0
    return subject.count('?')

def subject_all_caps_ratio(subject: str) -> float:
    if pd.isna(subject) or subject.strip() == '':
        return 0.0
    tokens = re.findall(r"\b\w+\b", subject)
    if not tokens:
        return 0.0
    caps = sum(1 for t in tokens if t.isalpha() and t.upper() == t and len(t) > 1)
    return caps / len(tokens)

def subject_personal_request(subject: str) -> int:
    if pd.isna(subject):
        return 0
    s = subject.lower()
    termos = ['senha', 'cpf', 'cartao', 'dados', 'confirmar', 'verifique', 'atualize', 'atualização', 'fatura', 'pagamento', 'bloqueio']
    return int(any(t in s for t in termos))

# =========================
# Carregamento e treino do modelo
# =========================

def carregar_base(caminho_csv: str) -> pd.DataFrame:
    df = pd.read_csv(caminho_csv)

    for col in ['subject', 'body', 'from']:
        if col not in df.columns:
            df[col] = ""

    if 'num_urls' not in df.columns:
        df['num_urls'] = (df['subject'].fillna('') + ' ' + df['body'].fillna('')).apply(contar_urls)

    if 'num_upper' not in df.columns:
        df['num_upper'] = (df['subject'].fillna('') + ' ' + df['body'].fillna('')).apply(contar_palavras_maiusculas)

    if 'urgency' not in df.columns:
        df['urgency'] = (df['subject'].fillna('') + ' ' + df['body'].fillna('')).apply(detectar_urgencia)

    if 'freq_email_access' not in df.columns:
        df['freq_email_access'] = 3

    df['from_domain'] = df['from'].apply(extrair_dominio)
    df['text'] = (df['subject'].fillna('') + ' ' + df['body'].fillna('')).apply(limpar_texto)

    # Parse do remetente para extrair display name, email local e domínio
    parsed = df['from'].apply(lambda r: pd.Series(parse_remetente(r)))
    parsed.columns = ['from_display', 'from_email', 'from_local', 'from_domain_parsed']
    # Prioriza o domínio extraído corretamente por parse_remetente (corrige casos com <>)
    df['from_display'] = parsed['from_display']
    df['from_email'] = parsed['from_email']
    df['from_local'] = parsed['from_local']
    # Se parse_remetente conseguiu domínio, usa-o; caso contrário mantém from_domain
    df['from_domain'] = parsed['from_domain_parsed'].where(parsed['from_domain_parsed'] != 'desconhecido', df['from_domain'])

    # Novas features
    df['text_len'] = (df['subject'].fillna('') + ' ' + df['body'].fillna('')).apply(comprimento_texto)
    df['special_chars'] = (df['subject'].fillna('') + ' ' + df['body'].fillna('')).apply(contar_caracteres_especiais)
    df['suspect_words'] = (df['subject'].fillna('') + ' ' + df['body'].fillna('')).apply(frequencia_palavras_suspeitas)

    # Features específicas do assunto
    df['subject_exclaim'] = df['subject'].fillna('').apply(subject_exclaim_count)
    df['subject_question'] = df['subject'].fillna('').apply(subject_question_count)
    df['subject_allcaps'] = df['subject'].fillna('').apply(subject_all_caps_ratio)
    df['subject_personal'] = df['subject'].fillna('').apply(subject_personal_request)

    # Features do remetente
    df['sender_spoof'] = df.apply(lambda r: sender_spoof_score(r.get('from_display', ''), r.get('from_local', ''), r.get('from_domain', 'desconhecido')), axis=1)

    # Link encurtado
    df['short_link'] = (df['subject'].fillna('') + ' ' + df['body'].fillna('')).apply(contem_link_encurtado)
    # Domínio suspeito
    df['suspect_domain'] = df['from_domain'].apply(dominio_suspeito)

    # Feature composta: alerta de phishing clássico
    df['alerta_phishing'] = [
        alerta_phishing(f"{row['subject']} {row['body']}", row['from_domain'])
        for _, row in df.iterrows()
    ]
    if 'label' not in df.columns:
        raise ValueError("A base precisa conter a coluna 'label' (0 = legitimo, 1 = phishing).")

    return df

def treinar_melhor_modelo(df: pd.DataFrame):
    from sklearn.ensemble import VotingClassifier, BaggingClassifier
    from sklearn.model_selection import cross_val_score, KFold
    
    features_num = [
        'num_urls', 'num_upper', 'urgency', 'freq_email_access', 'text_len', 'special_chars',
        'suspect_words', 'short_link', 'suspect_domain', 'alerta_phishing',
        # subject features
        'subject_exclaim', 'subject_question', 'subject_allcaps', 'subject_personal',
        # sender features
        'sender_spoof',
        # url features (adicionados dinamicamente no bloco de URL)
        'num_suspicious_urls','any_ip_url','any_basic_auth','any_punycode','avg_url_score'
    ]
    X = df[['text'] + features_num + ['from_domain']]
    y = df['label']

    # Balanceamento avançado usando uma combinação de técnicas
    df_bal = df.copy()
    phishing = df_bal[df_bal['label'] == 1]
    legit = df_bal[df_bal['label'] == 0]
    
    # 1. Oversampling balanceado
    if len(phishing) > 0 and len(legit) > 0:
        target_size = max(len(phishing), len(legit))
        if len(phishing) < len(legit):
            phishing_upsampled = resample(phishing, replace=True, n_samples=target_size, random_state=42)
            df_bal = pd.concat([legit, phishing_upsampled])
        else:
            legit_upsampled = resample(legit, replace=True, n_samples=target_size, random_state=42)
            df_bal = pd.concat([phishing, legit_upsampled])
    
    # 2. Feature engineering adicional
    df_bal['suspect_ratio'] = df_bal['suspect_words'] / df_bal['text_len'].replace(0, 1)
    df_bal['feature_score'] = (
        df_bal['urgency'] * 3 + 
        df_bal['short_link'] * 2 + 
        df_bal['suspect_domain'] * 2 +
        df_bal['num_urls'] + 
        df_bal['suspect_words'] +
        df_bal['suspect_ratio'] * 2
    ) / 11

    # Atualiza features para incluir novas métricas
    features_num += ['suspect_ratio', 'feature_score']
    X = df_bal[['text'] + features_num + ['from_domain']]
    y = df_bal['label']

    # Treina um IsolationForest com as mesmas features de texto (extrai features simples)
    try:
        global ISOLATION_MODEL
    except NameError:
        ISOLATION_MODEL = None

    try:
        # Extrai vetores numéricos simples para cada texto para treinar o detector de anomalias
        def _extrair_vetores_anomalia(texto_series: pd.Series):
            feats = []
            for t in texto_series.fillna(''):
                f = [
                    len(t),
                    len(re.findall(r'[A-Z]', t)) / (len(t) + 1),
                    len(re.findall(r'[!?]', t)) / (len(t) + 1),
                    len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', t)),
                    len(re.findall(r'\d+', t)) / (len(t) + 1)
                ]
                feats.append(f)
            return np.array(feats)

        X_anom = _extrair_vetores_anomalia(df_bal['text'])
        # Ajusta contaminação com base na proporção de phishing na base (limitar entre 0.01 e 0.2)
        prop_phishing = max(0.01, min(0.2, df_bal['label'].mean() if df_bal['label'].mean() > 0 else 0.01))
        ISOLATION_MODEL = IsolationForest(contamination=prop_phishing, random_state=42, n_estimators=100)
        ISOLATION_MODEL.fit(X_anom)
    except Exception:
        ISOLATION_MODEL = None

    # ------------------
    # Features relacionadas a URLs (treino)
    # ------------------
    try:
        def _analisar_urls_para_df(row):
            texto = (str(row.get('subject','')) + ' ' + str(row.get('body','')))
            urls = extrair_urls(texto)
            scores = [analisar_url(u, row.get('from_domain', None)) for u in urls]
            num_susp = sum(1 for s in scores if s['score'] > 0.5)
            any_ip = any(s['is_ip'] for s in scores)
            any_basic = any(s['uses_basic_auth'] or s['has_at_sign'] for s in scores)
            any_puny = any(s['is_punycode'] for s in scores)
            avg_score = float(np.mean([s['score'] for s in scores])) if scores else 0.0
            return pd.Series({'num_suspicious_urls': num_susp, 'any_ip_url': int(any_ip), 'any_basic_auth': int(any_basic), 'any_punycode': int(any_puny), 'avg_url_score': avg_score})

        urls_df = df_bal.apply(_analisar_urls_para_df, axis=1)
        df_bal = pd.concat([df_bal, urls_df], axis=1)
        # ensure new features present
        for col in ['num_suspicious_urls','any_ip_url','any_basic_auth','any_punycode','avg_url_score']:
            if col not in df_bal.columns:
                df_bal[col] = 0
        # Atualiza X
        features_num += ['num_suspicious_urls','any_ip_url','any_basic_auth','any_punycode','avg_url_score']
        X = df_bal[['text'] + features_num + ['from_domain']]
        y = df_bal['label']
    except Exception:
        pass

    # Reforço de peso para features críticas
    df['urgency'] = df['urgency'] * 2
    df['short_link'] = df['short_link'] * 2
    df['suspect_domain'] = df['suspect_domain'] * 2

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    preprocessador = ColumnTransformer(
        transformers=[
            ('tfidf', TfidfVectorizer(max_features=5000), 'text'),
            ('dom', OneHotEncoder(handle_unknown='ignore'), ['from_domain']),
            ('num', 'passthrough', features_num)
        ]
    )

    modelos = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            bootstrap=True,
            random_state=42
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            solver='liblinear',
            C=1.0,
            class_weight='balanced',
            random_state=42
        ),
        "Ensemble": VotingClassifier(
            estimators=[
                ('rf1', RandomForestClassifier(n_estimators=100, random_state=1)),
                ('rf2', RandomForestClassifier(n_estimators=100, random_state=2)),
                ('lr', LogisticRegression(max_iter=1000, random_state=3))
            ],
            voting='soft'
        )
    }

    melhor_modelo = None
    melhor_nome = None
    melhor_f1 = -1
    metricas_resumo = {}

    # Treina e avalia cada modelo com validação cruzada (F1) e usa média CV para selecionar o melhor
    for nome, modelo in modelos.items():
        pipe = Pipeline(steps=[
            ('preprocess', preprocessador),
            ('clf', modelo)
        ])

        # cross-val para obter F1 médio
        try:
            cv_scores = cross_val_score(pipe, X, y, cv=5, scoring='f1')
            cv_mean = float(np.mean(cv_scores))
        except Exception:
            # fallback: treina e avalia direto no split
            pipe.fit(X_train, y_train)
            y_pred = pipe.predict(X_test)
            cv_mean = f1_score(y_test, y_pred, zero_division=0)

        # treina no conjunto de treino para salvar/usar posteriormente
        try:
            pipe.fit(X_train, y_train)
            y_pred = pipe.predict(X_test)
        except Exception:
            y_pred = np.zeros_like(y_test)

        if hasattr(pipe.named_steps['clf'], "predict_proba"):
            try:
                y_proba = pipe.predict_proba(X_test)[:, 1]
                auc = roc_auc_score(y_test, y_proba)
            except Exception:
                auc = np.nan
        else:
            auc = np.nan

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        metricas_resumo[nome] = {
            "Acuracia": acc,
            "Precisao": prec,
            "Recall": rec,
            "F1": f1,
            "AUC": auc,
            "CV_F1": cv_mean
        }

        if cv_mean > melhor_f1:
            melhor_f1 = cv_mean
            melhor_modelo = pipe
            melhor_nome = nome

        # Calibra limiar ótimo para probabilidade (se possível) no conjunto de teste
        best_threshold = 0.5
        try:
            if melhor_modelo is not None and hasattr(melhor_modelo.named_steps['clf'], 'predict_proba'):
                y_proba = melhor_modelo.predict_proba(X_test)[:, 1]
                best_f1 = -1
                for th in np.linspace(0.1, 0.9, 81):
                    yp = (y_proba >= th).astype(int)
                    f = f1_score(y_test, yp, zero_division=0)
                    if f > best_f1:
                        best_f1 = f
                        best_threshold = float(th)
        except Exception:
            best_threshold = 0.5

        # salva threshold em metadata para uso posterior
        metricas_resumo['best_threshold'] = best_threshold

        return melhor_modelo, melhor_nome, metricas_resumo

def carregar_ou_treinar_modelo():
    # declarações globais antecipadas para evitar SyntaxError quando a função
    # atribui a ISOLATION_MODEL ou altera MODEL_THRESHOLD em diversos blocos
    global ISOLATION_MODEL, MODEL_THRESHOLD
    nome_arquivo = "modelo_phishing_melhor.pkl"
    caminho_csv = "base_emails_phishing.csv"
    iso_arquivo = "isolation_model.pkl"

    if os.path.exists(nome_arquivo):
        modelo = joblib.load(nome_arquivo)
        # tenta carregar modelo de anomalias se existir
        if os.path.exists(iso_arquivo):
            try:
                ISOLATION_MODEL = joblib.load(iso_arquivo)
            except Exception:
                ISOLATION_MODEL = None
        # tenta carregar metadata do modelo (threshold)
        meta_file = 'model_meta.json'
        try:
            if os.path.exists(meta_file):
                with open(meta_file, 'r', encoding='utf-8') as mf:
                    meta = json.load(mf)
                    MODEL_THRESHOLD = float(meta.get('best_threshold', MODEL_THRESHOLD))
        except Exception:
            pass
        return modelo, "Modelo carregado do arquivo .pkl", None, None

    if not os.path.exists(caminho_csv):
        st.error("Não foi encontrado o arquivo base_emails_phishing.csv nem o modelo salvo.")
        st.stop()

    df = carregar_base(caminho_csv)
    modelo, melhor_nome, metricas = treinar_melhor_modelo(df)
    joblib.dump(modelo, nome_arquivo)
    # salva também o isolation model (se treinado)
    try:
        if ISOLATION_MODEL is not None:
            joblib.dump(ISOLATION_MODEL, iso_arquivo)
    except Exception:
        pass
    # salva metadata (threshold) se disponível
    try:
        meta_file = 'model_meta.json'
        meta = {}
        if metricas and isinstance(metricas, dict) and 'best_threshold' in metricas:
            meta['best_threshold'] = float(metricas['best_threshold'])
        with open(meta_file, 'w', encoding='utf-8') as mf:
            json.dump(meta, mf)
    except Exception:
        pass

    return modelo, f"Modelo treinado usando {melhor_nome}.", metricas, df

# =========================
# Features de um novo e-mail
# =========================

def montar_features(subject, body, remetente, freq_email_access):
    texto_bruto = f"{subject} {body}"
    text = limpar_texto(texto_bruto)
    
    # Features básicas
    num_urls = contar_urls(texto_bruto)
    num_upper = contar_palavras_maiusculas(texto_bruto)
    urgency = detectar_urgencia(texto_bruto) * 2
    # Parse do remetente (display name, local, domain)
    remet_info = parse_remetente(remetente)
    from_display = remet_info.get('display_name', '')
    from_local = remet_info.get('local', '')
    from_domain = remet_info.get('domain', extrair_dominio(remetente))
    text_len = comprimento_texto(texto_bruto)
    special_chars = contar_caracteres_especiais(texto_bruto)
    suspect_words = frequencia_palavras_suspeitas(texto_bruto)
    short_link = contem_link_encurtado(texto_bruto) * 2
    
    # Análise avançada de domínio
    analise_dom = analisar_dominio(from_domain)
    suspect_domain = analise_dom["suspeito"] * 2
    domain_score = analise_dom["score_suspeitabilidade"]
    
    # Análise linguística
    ling = analisar_linguagem(texto_bruto)
    
    # Detecção de anomalias
    anomalia = detectar_anomalias_texto(texto_bruto)

    # Features específicas do assunto
    subject_exclaim = subject_exclaim_count(subject)
    subject_question = subject_question_count(subject)
    subject_allcaps = subject_all_caps_ratio(subject)
    subject_personal = subject_personal_request(subject)

    # Pontuação de spoof do remetente
    sender_spoof = sender_spoof_score(from_display, from_local, from_domain)
    
    # Alerta composto
    alerta = alerta_phishing(texto_bruto, from_domain)
    
    # Score final ponderado (usa WEIGHTS configuráveis)
    try:
        w = WEIGHTS
        total_w = sum(w.values()) if sum(w.values()) > 0 else 1.0
        phishing_score = (
            urgency * w.get('urgency', 0.15) +
            short_link * w.get('short_link', 0.2) +
            suspect_domain * w.get('suspect_domain', 0.25) +
            domain_score * w.get('domain_score', 0.15) +
            ling["emocional"] * w.get('emocional', 0.1) +
            ling["comandos"] * w.get('comandos', 0.1) +
            (anomalia) * w.get('anomalia', 0.05)
        ) / float(total_w)
    except Exception:
        phishing_score = (
            urgency * 0.15 +
            short_link * 0.2 +
            suspect_domain * 0.25 +
            domain_score * 0.15 +
            ling["emocional"] * 0.1 +
            ling["comandos"] * 0.1 +
            (anomalia) * 0.05
        )

    df = pd.DataFrame([{
        "text": text,
        "num_urls": num_urls,
        "num_upper": num_upper,
        "urgency": urgency,
        "freq_email_access": freq_email_access,
        "from_domain": from_domain,
        "from_display": from_display,
        "from_local": from_local,
        "text_len": text_len,
        "special_chars": special_chars,
        "suspect_words": suspect_words,
        "short_link": short_link,
        "suspect_domain": suspect_domain,
        "domain_score": domain_score,
        "subject_exclaim": subject_exclaim,
        "subject_question": subject_question,
        "subject_allcaps": subject_allcaps,
        "subject_personal": subject_personal,
        "sender_spoof": sender_spoof,
        "erros_gramaticais": ling["erros_gramaticais"],
        "formalidade": ling["formalidade"],
        "emocional": ling["emocional"],
        "comandos": ling["comandos"],
    "anomalia": anomalia,
        "phishing_score": phishing_score,
        "alerta_phishing": alerta
    }])
    return df

# =========================
# Interface Streamlit
# =========================

st.set_page_config(
    page_title="Detector de Phishing - Protótipo Acadêmico",
    layout="centered"
)

st.title("📧 Detector de E-mails de Phishing")
st.caption("Protótipo funcional desenvolvido para fins acadêmicos.")

with st.expander("ℹ️ Sobre o protótipo", expanded=False):
    st.write(
        """
        Este sistema utiliza técnicas de aprendizado de máquina para classificar e-mails como
        **legítimos (0)** ou **phishing (1)**, com base em:
        - Conteúdo textual (TF-IDF),
        - Número de links,
        - Palavras em caixa alta,
        - Presença de termos de urgência,
        - Domínio do remetente,
        - Frequência de acesso a e-mails (comportamental).
        """
    )

st.write("### Carregando modelo...")
modelo, msg_status, metricas_modelos, df_treino = carregar_ou_treinar_modelo()
st.success(msg_status)

# -----------------
# UI: Ajustes/Tuning
# -----------------
if 'model_weight' not in st.session_state:
    st.session_state.model_weight = 0.7
if 'final_threshold' not in st.session_state:
    st.session_state.final_threshold = MODEL_THRESHOLD
if 'weights' not in st.session_state:
    st.session_state.weights = WEIGHTS.copy()

with st.sidebar.expander('⚙️ Ajustes e calibração', expanded=False):
    st.write('Ajuste pesos das heurísticas e o peso do modelo na decisão final.')
    st.session_state.weights['urgency'] = st.slider('Peso: Urgência', 0.0, 1.0, float(st.session_state.weights.get('urgency', 0.15)), 0.01)
    st.session_state.weights['short_link'] = st.slider('Peso: Link encurtado', 0.0, 1.0, float(st.session_state.weights.get('short_link', 0.2)), 0.01)
    st.session_state.weights['suspect_domain'] = st.slider('Peso: Domínio suspeito', 0.0, 1.0, float(st.session_state.weights.get('suspect_domain', 0.25)), 0.01)
    st.session_state.weights['domain_score'] = st.slider('Peso: Score do domínio', 0.0, 1.0, float(st.session_state.weights.get('domain_score', 0.15)), 0.01)
    st.session_state.weights['emocional'] = st.slider('Peso: Linguagem emocional', 0.0, 1.0, float(st.session_state.weights.get('emocional', 0.1)), 0.01)
    st.session_state.weights['comandos'] = st.slider('Peso: Comandos', 0.0, 1.0, float(st.session_state.weights.get('comandos', 0.1)), 0.01)
    st.session_state.weights['anomalia'] = st.slider('Peso: Anomalia', 0.0, 1.0, float(st.session_state.weights.get('anomalia', 0.05)), 0.01)
    st.session_state.model_weight = st.slider('Peso do modelo na decisão final (0 = só heurísticas, 1 = só modelo)', 0.0, 1.0, float(st.session_state.model_weight), 0.01)
    st.session_state.final_threshold = st.slider('Limiar final para decisão (combined score)', 0.0, 1.0, float(st.session_state.final_threshold), 0.01)
    if st.button('Usar limiar calibrado salvo'):
        st.session_state.final_threshold = MODEL_THRESHOLD
        st.success(f'Limiar ajustado para {MODEL_THRESHOLD:.2f}')

    st.write('Dica: ajuste o peso do modelo e o limiar para reduzir falsos positivos/negativos localmente.')

# Atualiza variáveis globais com ajustes do usuário
WEIGHTS.update(st.session_state.weights)
MODEL_THRESHOLD = float(st.session_state.final_threshold)

if metricas_modelos:
    st.write("### Desempenho dos modelos (resumo)")
    tabela = pd.DataFrame(metricas_modelos).T
    st.dataframe(tabela.style.format("{:.3f}"), use_container_width=True)

st.write("### Testar um e-mail")

# Inicializar estado da análise
if 'analise_realizada' not in st.session_state:
    st.session_state.analise_realizada = False

# Inicializar valores padrão se não existirem
if 'form_state' not in st.session_state:
    st.session_state.form_state = {
        'subject': "",
        'remetente': "",
        'body': "",
        'freq': 3
    }

# Função para limpar campos
def limpar_campos():
    # Reseta tanto o dict de form_state quanto as chaves dos widgets
    st.session_state.form_state = {
        'subject': "",
        'remetente': "",
        'body': "",
        'freq': 3
    }
    # Reset widgets (as chaves usadas pelos inputs)
    try:
        st.session_state['subject_input'] = ""
    except Exception:
        pass
    try:
        st.session_state['remetente_input'] = ""
    except Exception:
        pass
    try:
        st.session_state['body_input'] = ""
    except Exception:
        pass
    try:
        st.session_state['freq_input'] = 3
    except Exception:
        pass

    st.session_state.analise_realizada = False
    # Não chamamos st.experimental_rerun() pois algumas versões do Streamlit
    # não a expõem. O Streamlit irá reexecutar o script automaticamente após
    # o clique do botão; retornar da função é suficiente para aplicar o novo
    # estado em uma nova execução.
    return

col1, col2 = st.columns(2)
with col1:
    subject = st.text_input("Assunto do e-mail", 
                           value=st.session_state.form_state['subject'], 
                           key="subject_input")
with col2:
    remetente = st.text_input("Remetente (ex: suporte@banco.com)", 
                             value=st.session_state.form_state['remetente'], 
                             key="remetente_input")

body = st.text_area("Corpo do e-mail", 
                   height=200, 
                   value=st.session_state.form_state['body'], 
                   key="body_input")

freq = st.slider(
    "Com que frequência o usuário acessa o e-mail? (1 = raramente, 5 = várias vezes ao dia)",
    min_value=1,
    max_value=5,
    value=st.session_state.form_state['freq'],
    key="freq_input"
)

# Botões Limpar e Analisar lado a lado
col_botoes1, col_botoes2 = st.columns(2)
with col_botoes1:
    if st.button("Limpar", key="limpar_button"):
        limpar_campos()

# Atualizar valores na sessão
st.session_state.form_state['subject'] = subject
st.session_state.form_state['remetente'] = remetente
st.session_state.form_state['body'] = body
st.session_state.form_state['freq'] = freq

with col_botoes2:
    if st.button("Analisar e-mail"):
        st.session_state.analise_realizada = True
        if subject.strip() == "" and body.strip() == "":
            st.warning("Preencha ao menos o assunto ou o corpo do e-mail para análise.")
        else:
            X_novo = montar_features(subject, body, remetente, freq)
            from_dom = X_novo['from_domain'].iloc[0]
            X_novo = montar_features(subject, body, remetente, freq)
            from_dom = X_novo['from_domain'].iloc[0]

            # Análise detalhada
            st.write("### 🔍 Análise Detalhada")
            
            # Pontuação geral
            phishing_score = X_novo['phishing_score'].iloc[0]
            st.write(f"Score de Phishing: **{phishing_score:.2%}**")
            
            # Análise do domínio
            st.write("#### 🌐 Análise do Domínio")
            analise_dom = analisar_dominio(from_dom)
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"- Domínio: `{from_dom}`")
                # Mostrar display name e local-part quando disponíveis
                disp = X_novo.get('from_display', pd.Series(['']))[0]
                localp = X_novo.get('from_local', pd.Series(['']))[0]
                st.write(f"- Confiável: {'✅ Sim' if dominio_confiavel(from_dom) else '❌ Não'}")
                if disp:
                    st.write(f"- Nome do remetente: `{disp}`")
                if localp:
                    st.write(f"- Local-part do e-mail: `{localp}`")
            with col2:
                st.write(f"- Score de Suspeitabilidade: {analise_dom['score_suspeitabilidade']:.2%}")
                if analise_dom['razao']:
                    st.write(f"- Razões: {analise_dom['razao']}")
            # Mostrar score de spoof do remetente
            spoof_score = X_novo.get('sender_spoof', pd.Series([0.0]))[0]
            st.write(f"- Sender spoof score: **{spoof_score:.2f}**")
            
            # Análise do conteúdo
            st.write("#### 📝 Análise do Conteúdo")
            col3, col4 = st.columns(2)
            with col3:
                st.write("Indicadores:")
                st.write(f"- Links encurtados: {'🚨 Sim' if X_novo['short_link'].iloc[0] else '✅ Não'}")
                st.write(f"- Urgência: {'🚨 Alta' if X_novo['urgency'].iloc[0] > 0 else '✅ Normal'}")
                st.write(f"- Palavras suspeitas: {X_novo['suspect_words'].iloc[0]}")
                # URLs extraídas e análise
                urls = extrair_urls(subject + ' ' + body)
                if urls:
                    st.write('- URLs encontradas:')
                    for u in urls:
                        info = analisar_url(u, from_dom)
                        st.write(f"  - {info['url']} -> score: {info['score']:.2f} | domain: {info['domain']} | https: {info['is_https']} | ip: {info['is_ip']}")
                else:
                    st.write('- URLs encontradas: nenhuma')
            with col4:
                st.write("Análise Linguística:")
                st.write(f"- Formalidade: {X_novo['formalidade'].iloc[0]:.2%}")
                st.write(f"- Emocional/Urgência: {X_novo['emocional'].iloc[0]:.2%}")
                st.write(f"- Comandos diretos: {X_novo['comandos'].iloc[0]:.2%}")
            
            # Alerta de anomalias
            if X_novo['anomalia'].iloc[0]:
                st.warning("⚠️ Anomalias detectadas no padrão do texto")
            # Mostrar conteúdo atual da whitelist para ver se dominio já foi salvo
            wl_path = os.path.join(os.getcwd(), 'whitelist.txt')
            if os.path.exists(wl_path):
                try:
                    with open(wl_path, 'r', encoding='utf-8') as f:
                        wl_items = [l.strip() for l in f if l.strip()]
                except Exception:
                    wl_items = []
            else:
                wl_items = []
            st.write(f"whitelist.txt: {wl_items}")

            # Se o domínio for confiável, ignora o modelo e considera legítimo
            if dominio_confiavel(from_dom):
                st.success("🟢 Resultado: **Provavelmente LEGÍTIMO** (domínio confiável).")
                st.write(f"Domínio do remetente '{from_dom}' está na whitelist ou é conhecido como confiável.")
            else:
                # Regra dura: se alerta_phishing == 1, retorna phishing
                if X_novo['alerta_phishing'].iloc[0] == 1:
                    st.error("🔴 Resultado: **PHISHING detectado por regra!**")
                    st.write("Este e-mail possui link encurtado, termo de urgência e domínio suspeito.")
                else:
                    # obtém probabilidade do modelo quando disponível
                    prob = 0.0
                    try:
                        if hasattr(modelo.named_steps['clf'], 'predict_proba'):
                            prob = float(modelo.predict_proba(X_novo)[0, 1])
                        else:
                            # fallback: usar predict como 0/1
                            pred = int(modelo.predict(X_novo)[0])
                            prob = float(pred)
                    except Exception:
                        prob = 0.0

                    phishing_score = float(X_novo['phishing_score'].iloc[0])
                    model_w = float(st.session_state.model_weight)
                    combined = model_w * prob + (1.0 - model_w) * phishing_score

                    st.write(f"- Probabilidade (modelo): **{prob:.2%}**")
                    st.write(f"- Score heurístico (phishing_score): **{phishing_score:.2%}**")
                    st.write(f"- Combined score: **{combined:.2%}** (threshold = {MODEL_THRESHOLD:.2f})")

                    if combined >= MODEL_THRESHOLD:
                        st.error("� Resultado: **Possível PHISHING** (score combinado).")
                    else:
                        st.success("🟢 Resultado: **Provavelmente LEGÍTIMO**.")

            if st.session_state.analise_realizada:
                with st.expander("Ver features calculadas para este e-mail"):
                    st.write(X_novo)
                    st.info(f"Valor de alerta_phishing: {X_novo['alerta_phishing'].iloc[0]}")
                    dominio_atual = X_novo['from_domain'].iloc[0]
                    st.write(f"Dominio do remetente: **{dominio_atual}**")
                    if st.button("Marcar remetente como confiável"):
                        save_whitelist(dominio_atual)
                        st.success(f"Domínio '{dominio_atual}' adicionado à whitelist.")
                        st.experimental_rerun()