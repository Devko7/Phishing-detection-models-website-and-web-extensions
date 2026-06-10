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

# Main writer: David Vasilev
# Reviewer: Theodotos Neokleous
# Contributor: -
def load_human_generated_dataset() -> pd.DataFrame:
    """
    Load and combine the human-generated phishing and legitimate email datasets.

    Returns a DataFrame with columns:
    - sender
    - receiver
    - date
    - subject
    - body
    - urls
    - label (1 = phishing, 0 = legitimate)
    """
    project_root = Path(__file__).resolve().parents[2]
    data_dir = project_root / "email-data" / "data" / "human-generated"

    phishing_path = data_dir / "phishing.csv"
    legit_path = data_dir / "legit.csv"

    phishing_df = pd.read_csv(phishing_path)
    legit_df = pd.read_csv(legit_path)

    # Combine the two datasets into one table
    df = pd.concat([phishing_df, legit_df], ignore_index=True)

    # Drop rows without text content
    df = df.dropna(subset=["subject", "body"])

    return df

# Main writer: David Vasilev
# Reviewer: Theodotos Neokleous
# Contributor: -
def build_decision_tree_pipeline(max_depth: int | None = None) -> Pipeline:
    """
    A simple text classification pipeline:
    - Concatenate email subject and body
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
                    ngram_range=(1, 2),
                    lowercase=True,
                    stop_words="english",
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

# Main writer: David Vasilev
# Reviewer: Theodotos Neokleous
# Contributor: -
def build_calibrated_model(base_model: Pipeline, *, method: str = "sigmoid", cv: int = 5):
    """
    Wrap the base model with probability calibration.
    """
    params = dict(method=method, cv=cv)
    sig = inspect.signature(CalibratedClassifierCV)
    if "estimator" in sig.parameters:
        return CalibratedClassifierCV(estimator=base_model, **params)
    return CalibratedClassifierCV(base_estimator=base_model, **params)

# Main writer: David Vasilev
# Reviewer: Theodotos Neokleous
# Contributor: -
def train_and_evaluate(max_depth: int | None = None) -> Pipeline:
    """
    Train the decision tree classifier on the human-generated dataset
    and print a simple evaluation report.

    Returns the fitted Pipeline instance.
    """
    df = load_human_generated_dataset()

    X_text = (df["subject"].fillna("") + " " + df["body"].fillna("")).astype(str)
    y = df["label"].astype(int)

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
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))

    return model

# Main writer: David Vasilev
# Reviewer: Theodotos Neokleous
# Contributor: -
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decision tree classifier for phishing vs. legitimate emails."
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum depth of the decision tree (default: 10).",
    )
    parser.add_argument(
        "--subject",
        type=str,
        help="Email subject to classify.",
    )
    parser.add_argument(
        "--body",
        type=str,
        help="Email body to classify.",
    )

    args = parser.parse_args()

    # Always train the model on the full training data first.
    model = train_and_evaluate(max_depth=args.max_depth)
    joblib.dump(model, "Email Prediction Models/AI Models/human_email_phishing_classifier.joblib")

    # If subject/body are provided, run a single prediction.
    if args.subject is not None or args.body is not None:
        subject = args.subject or ""
        body = args.body or ""
        text = f"{subject} {body}".strip()

        if not text:
            print("\nNo subject/body text provided for prediction.")
            return

        pred = int(model.predict([text])[0])
        proba = model.predict_proba([text])[0]
        legit_probability = float(proba[0])
        phishing_probability = float(proba[1])
        label = "phishing" if pred == 1 else "legit"
        confidence = phishing_probability if pred == 1 else legit_probability

        print("\nSingle email prediction:")
        print(f"Subject: {subject}")
        print(f"Body: {body}")
        print(f"Predicted label: {label}")
        print(f"Confidence: {confidence:.3f}")
        print(f"Phishing probability: {phishing_probability:.3f}")
        print(f"Legit probability: {legit_probability:.3f}")


if __name__ == "__main__":
    main()

