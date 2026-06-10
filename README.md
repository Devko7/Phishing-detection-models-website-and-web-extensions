# Email & URL Phishing and LLM Generation Detector
By: Cyber Security Group 6
<br>
Umbrella Topic: Authentication

# Prerequisites
This project requires Python `3.12`. To create and activate venv:
```bash
python -m venv venv
source venv/bin/activate  #on windows: venv\Scripts\activate
```
To install the relevant dependencies you can run:
```bash
pip install -r requirements.txt
```

# Running the API
You can run the API that makes calls to all of the trained and deterministic models using the following command:
```bash
python "APIs/Website_API.py"
```

# Website
> [!WARNING]
> The Website requires the API to be running for full functionality.

After the API has been started, you can open the website from `Website/index.html` and use it in the following ways:
- Type a URL in the URL input box
- Type an email subject and body in their respective boxes

Afterwards you can press one of the buttons below the text boxes to predict phishing and LLM-generation using either the AI models or the Deterministic models. The results will be printed to the right of the text boxes with a confidence percentage.

# Web Extensions
> [!WARNING]
> The Web Extensions require the API to be running for full functionality and only on a Chromium-based browser.

Two Web Extensions are provided:
- Email Web Extension - for detecting phishing and LLM-usage in emails from Gmail.
- URL Web Extension - for detecting phishing URLs.

### How to Setup:
In order to use the web extensions you need to follow these steps:
1. Download the repository locally
2. Run the API (Go to "Running the API" section for instructions)
3. Open the extensions tab on your Chromium-based browser of choice, like `chrome://extensions/`.
4. Make sure the **Developer mode** option is enabled.
5. Click on **Load unpacked** and choose the `Email Web Extension` and/or `URL Web Extension` folders from the repository root to load the each web extension.

Instructions on how to use the web extensions are provided in the sections below.

## Email Web Extension
> [!WARNING]
> The Email Web Extension works only on Gmail.

After you have uploaded the `Email Web Extension` package to your extensions, open Gmail and open an email of your choice. You will see an "Checking email" popup at the bottom-right corner of your screen. If you open the web extension from the top-right corner of your browser you will se the results from the predictions displayed.

## URL Web Extension
After you have uploaded the `URL Web Extension` package to your extensions, open any site you want in your browser. If the calls to the API determine the URL you are trying to visit is phishing, defacement, or malware a "Connection Blocked" screen will appear on the page.

# Training Models
Email dataset is found [here](https://www.kaggle.com/datasets/francescogreco97/human-llm-generated-phishing-legitimate-emails?resource=download), URL dataset is found [here](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset)
Before using the models for predicitons on the website the models have to be trained. Use the following command inside root to train the models:
```bash
python <path to model>
```

**Example:**
```bash
python "Email Prediction Models/AI Models/human_email_phishing_classifier.py"
```

> [!IMPORTANT]
> All models have been trained and saved to their corresponding joblib files. You do **not** need to retrain them to use the API. You can find the models inside: `Email Prediction Models` for the email models and `URL Prediction Models` for the URL models.

# Experiments Scripts

> [!WARNING]
> The Experiment scripts require the API to be running for full functionality.

The scripts for the experiments and the data they produce are stored in the `Experiments` pakcage. They make calls on a limited number of emails/URLs in the datasets to every model through the API. You can run them using the following format:
```bash
python <path to script>
```

**Example:**
```bash
python "Experiments/email_experiments_script.py"
```
