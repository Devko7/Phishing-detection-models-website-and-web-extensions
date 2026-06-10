from pathlib import Path
import argparse
import joblib
import inspect

import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score

# Main writer: Jon Zdovc
# Reviewer: David Vasilev
# Contributor: -
def robust_read_csv(filename: Path) -> pd.DataFrame:
    """
    Handles CSVs where the text column might contain unquoted commas.
    """
    try:
        return pd.read_csv(filename)
    except Exception:
        data = []
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            f.readline() # Skip header
            for line in f:
                line = line.strip()
                if not line: continue
                parts = line.rsplit(',', 1)
                if len(parts) == 2:
                    data.append(parts)
                else:
                    data.append([line, None])
        return pd.DataFrame(data, columns=['text', 'label'])

# Main writer: Jon Zdovc
# Reviewer: David Vasilev
# Contributor: -
def load_and_prepare_data() -> pd.DataFrame:
    """
    Locates and merges Human and LLM datasets.
    """
    project_root = Path(__file__).resolve().parents[2]
    data_dir = project_root / "email-data" / "data"

    # Load Human Data
    h_legit = pd.read_csv(data_dir / "human-generated" / "legit.csv")
    h_phish = pd.read_csv(data_dir / "human-generated" / "phishing.csv")
    human_df = pd.concat([h_legit, h_phish], ignore_index=True)
    human_df['content'] = (human_df['subject'].fillna('') + " " + human_df['body'].fillna('')).astype(str)
    human_df['is_llm'] = 0

    # Load LLM Data
    l_legit = robust_read_csv(data_dir / "llm-generated" / "legit.csv")
    l_phish = robust_read_csv(data_dir / "llm-generated" / "phishing.csv")
    llm_df = pd.concat([l_legit, l_phish], ignore_index=True)
    llm_df['content'] = llm_df['text'].fillna('').astype(str)
    llm_df['is_llm'] = 1

    df = pd.concat([human_df[['content', 'is_llm']], llm_df[['content', 'is_llm']]], ignore_index=True)
    return df.dropna(subset=['content'])

# Main writer: Jon Zdovc
# Reviewer: David Vasilev
# Contributor: -
def build_classifier_pipeline(max_depth: int | None = 15) -> Pipeline:
    return Pipeline(steps=[
        ("tfidf", TfidfVectorizer(
            max_features=10000,
            ngram_range=(1, 2),
            lowercase=True,
            stop_words="english"
        )),
        ("clf", DecisionTreeClassifier(
            criterion="gini",
            max_depth=max_depth,
            random_state=42
        ))
    ])

# Main writer: Jon Zdovc
# Reviewer: David Vasilev
# Contributor: -
def build_calibrated_model(base_model: Pipeline, method: str = "sigmoid", cv: int = 5):
    params = dict(method=method, cv=cv)
    sig = inspect.signature(CalibratedClassifierCV)
    param_name = "estimator" if "estimator" in sig.parameters else "base_estimator"
    return CalibratedClassifierCV(**{param_name: base_model}, **params)

# Main writer: Jon Zdovc
# Reviewer: David Vasilev
# Contributor: -
def train_and_evaluate(max_depth: int | None = 15):
    df = load_and_prepare_data()

    X = df['content']
    y = df['is_llm']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    base_pipe = build_classifier_pipeline(max_depth=max_depth)
    model = build_calibrated_model(base_pipe)

    print(f"Training on {len(X_train)} samples...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"\nModel Accuracy: {accuracy_score(y_test, y_pred):.3f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Human", "AI/LLM"]))

    return model

# Main writer: Jon Zdovc
# Reviewer: David Vasilev
# Contributor: -
def main():
    parser = argparse.ArgumentParser(description="Detector for Human vs. LLM-generated emails.")
    parser.add_argument("--max-depth", type=int, default=15, help="Max depth for the Decision Tree.")
    parser.add_argument("--text", type=str, help="Full email text to classify.")

    args = parser.parse_args()

    # Train and save
    model = train_and_evaluate(max_depth=args.max_depth)
    save_path = Path("Email Prediction Models/AI Models/llm_detector_classifier.joblib")
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, save_path)
    print(f"\nModel saved to: {save_path}")


    if args.text:
        pred = int(model.predict([args.text])[0])
        proba = model.predict_proba([args.text])[0]

        label = "AI/LLM-generated" if pred == 1 else "Human-written"
        confidence = proba[pred]

        print("\n--- Single Prediction ---")
        print(f"Input Text: {args.text[:100]}...")
        print(f"Result: {label}")
        print(f"Confidence: {confidence:.3f}")

if __name__ == "__main__":
    main()
