import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import seaborn as sns
import os


def load_data(file_path):
    """
    Load the preprocessed data from CSV file and remove zero-valued columns.
    """
    df = pd.read_csv(file_path)
    print(f"Original data shape: {df.shape}")

    # Remove columns where all values are zero
    zero_columns = df.columns[(df == 0).all()].tolist()
    df = df.drop(columns=zero_columns)

    print(f"Data shape after removing zero-valued columns: {df.shape}")
    print(f"Removed columns: {zero_columns}")

    return df


def apply_isolation_forest(df):
    """
    Apply Isolation Forest algorithm to detect anomalies.
    """
    # Ensure we're only using numeric columns for the Isolation Forest
    numeric_columns = df.select_dtypes(include=[np.number]).columns
    X = df[numeric_columns]

    clf = IsolationForest(contamination=0.1, random_state=42)
    df['anomaly'] = clf.fit_predict(X)
    df['anomaly_score'] = clf.decision_function(X)
    return df


def analyze_anomalies(df):
    """
    Analyze detected anomalies and print summary statistics.
    """
    anomalies = df[df['anomaly'] == -1]
    print(f"\nTotal data points: {len(df)}")
    print(f"Anomalies detected: {len(anomalies)} ({len(anomalies) / len(df) * 100:.2f}%)")

    summary = []
    print("\nMean values for normal vs anomalous data points:")
    for column in df.columns[:-2]:  # Exclude 'anomaly' and 'anomaly_score' columns
        normal_mean = df[df['anomaly'] == 1][column].mean()
        anomaly_mean = anomalies[column].mean()
        difference = abs(normal_mean - anomaly_mean)
        print(f"{column}:")
        print(f"  Normal: {normal_mean:.4f}")
        print(f"  Anomaly: {anomaly_mean:.4f}")
        print(f"  Difference: {difference:.4f}")
        print()
        summary.append({
            'column': column,
            'normal_mean': normal_mean,
            'anomaly_mean': anomaly_mean,
            'difference': difference
        })

    return pd.DataFrame(summary)


def visualize_anomalies(df, assets_folder):
    """
    Create visualizations to help understand the anomalies and save them to the assets folder.
    """
    # Ensure the assets folder exists
    os.makedirs(assets_folder, exist_ok=True)

    # Correlation heatmap
    plt.figure(figsize=(12, 10))
    mask = np.triu(np.ones_like(df.corr(), dtype=bool))
    sns.heatmap(df.corr(), mask=mask, annot=True, cmap='coolwarm', linewidths=0.5, fmt='.2f')
    plt.title('Feature Correlation Heatmap')
    plt.tight_layout()
    plt.savefig(os.path.join(assets_folder, 'correlation_heatmap.png'))
    plt.close()

    # Scatter plot of two most important features
    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x=df.columns[0], y=df.columns[1], hue='anomaly', palette={1: 'blue', -1: 'red'})
    plt.title(f'Anomalies based on {df.columns[0]} and {df.columns[1]}')
    plt.savefig(os.path.join(assets_folder, 'anomalies_scatter_plot.png'))
    plt.close()

    # Distribution of anomaly scores
    plt.figure(figsize=(10, 6))
    sns.histplot(data=df, x='anomaly_score', hue='anomaly', kde=True, palette={1: 'blue', -1: 'red'})
    plt.title('Distribution of Anomaly Scores')
    plt.savefig(os.path.join(assets_folder, 'anomaly_scores_distribution.png'))
    plt.close()


def main(file_path, assets_folder, output_csv):
    """
    Main function to orchestrate the analysis process.
    """
    # Load the data
    df = load_data(file_path)

    # Apply Isolation Forest
    df = apply_isolation_forest(df)

    # Analyze anomalies
    summary_df = analyze_anomalies(df)

    # Save summary to CSV
    summary_df.to_csv(output_csv, index=False)
    print(f"Summary saved to {output_csv}")

    # Visualize anomalies
    visualize_anomalies(df, assets_folder)
    print(f"Visualizations saved to {assets_folder}")

    return df


if __name__ == "__main__":
    file_path = '../data/isolation_forest_data_refined.csv'
    assets_folder = '../assets'
    output_csv = '../assets/anomaly_summary.csv'
    df = main(file_path, assets_folder, output_csv)