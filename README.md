# 🚀 AI Scam Detector
An AI-powered scam detection system that analyzes suspicious messages using **rule-based signals + Large Language Models (LLMs)** to detect fraud patterns and provide actionable advice.

## 🔥 Features

* 🧠 **AI-powered analysis** using OpenAI
* 🚨 Detects common scams:

  * OTP scams
  * Phishing links
  * Lottery / prize scams
  * Bank / KYC fraud
* 🎯 Identifies **psychological manipulation tactics**:

  * Urgency
  * Fear
  * Authority
  * Greed
* 📊 Provides:

  * Risk score (0–100)
  * Risk level (Low / Medium / High)
  * Scam type detection
  * AI-generated explanation
  * Safety advice
* 💻 Clean and interactive frontend UI

---

## 🛠 Tech Stack

* **Backend:** FastAPI
* **Frontend:** HTML, CSS, JavaScript
* **AI Model:** OpenAI API
* **Other:** Python, dotenv

---

## 📂 Project Structure

```
ai-scam-detector/
│
├── backend/
│   ├── main.py
│   ├── detector.py
│   ├── matcher.py
│   ├── playbook.py
│   ├── ai_analyzer.py
│   ├── prompts.py
│   └── routes/
│       └── analyse.py
│
├── frontend/
│   └── index.html
│
├── .env
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup & Run Locally

### 1️⃣ Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ai-scam-detector.git
cd ai-scam-detector
```

### 2️⃣ Create virtual environment

```bash
python -m venv venv
venv\Scripts\activate   # Windows
```

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Add environment variable

Create a `.env` file in root:

```env
OPENAI_API_KEY=your_api_key_here
```

---

### 5️⃣ Run backend

```bash
uvicorn backend.main:app --reload
```

---

### 6️⃣ Open frontend

Open this file in browser:

```
frontend/index.html
```

---

## 🧪 Example

### Input:

```
Congratulations! You won ₹50,000. Click link now.
```

### Output:

* 🔴 High Risk
* 🎯 Scam Type: Lottery Scam
* ⚠️ Signals detected
* 🧠 AI explanation
* 📌 Advice provided

---

## 🌐 API Endpoints

* `GET /` → Health check
* `POST /api/analyze` → Analyze message

---

## 📸 Screenshots

*(Add your UI screenshots here)*

---

## 🚀 Future Improvements

* 🔐 User authentication
* 📊 History tracking (database)
* 📱 Mobile app / Chrome extension
* 🌍 Deployment (Render / Vercel)

---

## 💼 Project Summary (for Resume)

> Built an AI-powered scam detection system using FastAPI and OpenAI that analyzes messages, detects fraud patterns, and provides risk scoring and safety recommendations.

---

## ⚠️ Disclaimer

This tool provides **AI-assisted predictions** and should not be considered 100% accurate. Always verify sensitive information through official sources.

---

## ⭐ Contribute

Feel free to fork and improve the project!

---

