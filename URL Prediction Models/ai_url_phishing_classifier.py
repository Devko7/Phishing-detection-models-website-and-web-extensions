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

# Main writer: Sidra Al Khawam
# Reviewer: - 
# Contributor: Estelle Namekong
def load_dataset() -> pd.DataFrame:
    """
    Load URL dataset

    Returns a DataFrame with columns:
    - url
    - type (phishing, defacement, benign)
    """
    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "url-data" / "data"

    data_path = data_dir / "urls.csv"

    data_df = pd.read_csv(data_path)
    return data_df

# Main writer: Sidra Al Khawam
# Reviewer: - 
# Contributor: Estelle Namekong
def build_decision_tree_pipeline(max_depth: int | None = None) -> Pipeline:
    """
    A simple text classification pipeline:
    - Use a URL as input text
    - Convert text to TF-IDF features
    - Train a DecisionTreeClassifier on those features
    """

    # The actual "model" here is a sklearn Pipeline
    model = Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    max_features=10_000,
                    ngram_range=(1, 3),
                    lowercase=True,
                ),
            ),
            (
                "clf",
                DecisionTreeClassifier(
                    criterion="gini",
                    max_depth=max_depth,
                    random_state=42,
                ),
            ),
        ]
    )

    return model

# Main writer: Sidra Al Khawam
# Reviewer: - 
# Contributor: Estelle Namekong
def build_calibrated_model(base_model: Pipeline, *, method: str = "sigmoid", cv: int = 5):
    """
    Wrap the base model with probability calibration.
    """
    params = dict(method=method, cv=cv)
    sig = inspect.signature(CalibratedClassifierCV)
    if "estimator" in sig.parameters:
        return CalibratedClassifierCV(estimator=base_model, **params)
    return CalibratedClassifierCV(base_estimator=base_model, **params)

# Main writer: Estelle Namekong
# Reviewer: - 
# Contributor: Sidra Al Khawam
def train_and_evaluate(max_depth: int | None = None) -> Pipeline:
    """
    Train the decision tree classifier on the URL dataset
    and print a simple evaluation report.

    Returns the fitted Pipeline instance.
    """
    df = load_dataset()

    X_text = df["url"].astype(str)
    y = df["type"].astype(str)

    X_train, X_test, y_train, y_test = train_test_split(
        X_text,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    base_model = build_decision_tree_pipeline(max_depth=max_depth)
    model = build_calibrated_model(base_model, method="sigmoid", cv=5)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"Decision tree accuracy on test set: {acc:.3f}")
    print("\nDetailed classification report:\n")
    print(classification_report(y_test, y_pred))

    return model

# Main writer: Estelle Namekong
# Reviewer: - 
# Contributor: Sidra Al Khawam
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decision tree classifier for URL classification (phishing, defacement, benign)."
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum depth of the decision tree (default: 10).",
    )
    parser.add_argument(
        "--url",
        type=str,
        help="URL to classify.",
    )

    args = parser.parse_args()

    # Always train the model on the full training data first.
    model = train_and_evaluate(max_depth=args.max_depth)
    joblib.dump(model, "URL Prediction Models/url_classifier.joblib")

    # If URL is provided, run a single prediction.
    if args.url is not None:
        url = args.url.strip()

        if not url:
            print("\nNo URL provided for prediction.")
            return

        pred = model.predict([url])[0]
        proba = model.predict_proba([url])[0]

        classes = model.classes_
        class_probabilities = dict(zip(classes, proba))

        phishing_prob = class_probabilities.get("phishing", 0.0)
        defacement_prob = class_probabilities.get("defacement", 0.0)
        benign_prob = class_probabilities.get("benign", 0.0)

        phishing_probability = phishing_prob + defacement_prob
        legit_probability = benign_prob
        safe_label = "legit" if pred == "benign" else "phishing"
        confidence = class_probabilities[pred]

        print("\nSingle URL prediction:")
        print(f"URL: {url}")
        print(f"Predicted label: {safe_label}")
        print(f"Confidence: {confidence:.3f}")
        print(f"Phishing probability: {phishing_probability:.3f}")
        print(f"Legit probability: {legit_probability:.3f}")


if __name__ == "__main__":
    main()
