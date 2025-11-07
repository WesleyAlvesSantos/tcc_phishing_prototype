# 🛡️ Detector de Phishing em Emails

Sistema de detecção de phishing que utiliza machine learning e análise heurística para identificar emails suspeitos. Desenvolvido como parte do projeto de TCC II.

## ✨ Funcionalidades

- 🤖 Machine Learning para classificação de emails
- 📊 Análise detalhada de URLs e domínios
- 🔍 Detecção de anomalias em textos
- ⚡ Interface web interativa com Streamlit
- 📝 Sistema de whitelist persistente
- ⚙️ Pesos e parâmetros ajustáveis

## 🚀 Como Executar

### Pré-requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/detector-phishing.git
cd detector-phishing
```

### 2. Crie um ambiente virtual (recomendado)

```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Instale as dependências

```bash
pip install -r requirements.txt
```

Se o arquivo requirements.txt não existir, instale manualmente:

```bash
pip install streamlit pandas scikit-learn numpy joblib tld
```

### 4. Execute a aplicação

```bash
streamlit run modelo_phishing.py
```

O navegador abrirá automaticamente com a interface do sistema.

## 📁 Estrutura do Projeto

```
detector-phishing/
├── modelo_phishing.py     # Código principal
├── base_emails_phishing.csv    # Dataset de treino
├── whitelist.txt         # Lista de domínios confiáveis
├── requirements.txt      # Dependências do projeto
├── documentacao_tecnica.md    # Documentação detalhada
└── manual_usuario.md     # Manual do usuário
```

## 🛠️ Arquivos Gerados

Durante a execução, o sistema criará:
- `modelo_phishing_melhor.pkl`: Modelo treinado
- `isolation_model.pkl`: Modelo de detecção de anomalias
- `model_meta.json`: Configurações e metadados
- `whitelist.txt`: Domínios marcados como confiáveis

## 📊 Dataset

O arquivo `base_emails_phishing.csv` deve ter o seguinte formato:
```csv
subject,body,from,num_urls,num_upper,urgency,label
"Assunto","Corpo do email","remetente@dominio.com",0,0,0,0
```

Onde:
- `label`: 0 para emails legítimos, 1 para phishing
- Outros campos numéricos podem ser deixados como 0 (serão recalculados)

## ⚙️ Configuração

### Ajuste de Pesos

Na interface web, você pode ajustar:
- Peso de cada característica (0-1)
- Balanço entre modelo e heurísticas
- Limiar de decisão final

### Whitelist

Para adicionar domínios confiáveis:
1. Analise um email
2. Expanda "Ver features calculadas"
3. Clique em "Marcar remetente como confiável"

## 🔧 Troubleshooting

### Problemas Comuns

1. **Erro: ModuleNotFoundError**
   ```bash
   pip install <nome-do-modulo>
   ```

2. **Erro ao carregar modelo**
   ```bash
   # Remova arquivos .pkl e execute novamente
   # O sistema irá retreinar automaticamente
   ```

3. **Erro de memória**
   - Feche outras aplicações
   - Verifique se tem pelo menos 4GB RAM disponível

## 📈 Métricas

O sistema exibe em tempo real:
- Acurácia
- Precisão
- Recall
- F1-score
- ROC AUC

## 🤝 Contribuindo

1. Faça um Fork do projeto
2. Crie sua Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a Branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## ✨ Agradecimentos

- Orientador do TCC
- Comunidade Python/ML
- Contribuidores de bibliotecas open source

## 📞 Suporte

- Consulte a [Documentação Técnica](documentacao_tecnica.md)
- Veja o [Manual do Usuário](manual_usuario.md)
- Abra uma Issue no GitHub

## 🔍 Citação

Se este projeto foi útil para sua pesquisa, por favor cite:

```bibtex
@software{detector_phishing,
  author = {Seu Nome},
  title = {Detector de Phishing em Emails},
  year = {2025},
  url = {https://github.com/seu-usuario/detector-phishing}
}
```