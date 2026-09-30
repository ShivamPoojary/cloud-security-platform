#!/usr/bin/env python3
"""Standalone script to train the UEBA Isolation Forest model and initialize

behavioral baselines using synthetic normal cloud telemetry.
"""
import sys
import os
import argparse

# Ensure backend root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.ml.trainer import UEBATrainer
from app.ml.features import FEATURE_NAMES
from app.core.logging import logger


def main():
    parser = argparse.ArgumentParser(description="Train UEBA Isolation Forest Model")
    parser.add_argument("--samples", type=int, default=350, help="Number of baseline normal events to generate")
    parser.add_argument("--contamination", type=float, default=0.03, help="Contamination factor for Isolation Forest")
    parser.add_argument("--estimators", type=int, default=100, help="Number of isolation trees")
    parser.add_argument("--version", type=str, default="ueba-isolation-forest-v1", help="Model version identifier")
    parser.add_argument("--output", type=str, default=None, help="Custom target output path for model bundle")

    args = parser.parse_args()

    print("=" * 65)
    print("      UEBA ISOLATION FOREST MODEL TRAINING PIPELINE")
    print("=" * 65)
    print(f"Target Samples:       {args.samples}")
    print(f"Contamination:        {args.contamination}")
    print(f"Estimators:           {args.estimators}")
    print(f"Model Version:        {args.version}")
    print(f"Feature Space ({len(FEATURE_NAMES)} features):")
    for idx, f in enumerate(FEATURE_NAMES, 1):
        print(f"  {idx:2d}. {f}")
    print("-" * 65)

    trainer = UEBATrainer(
        model_version=args.version,
        contamination=args.contamination,
        n_estimators=args.estimators,
    )

    print("Generating diverse operational cloud telemetry...")
    report = trainer.train_default(sample_count=args.samples, save_path=args.output)

    print("\nTraining completed successfully!")
    print(f"Saved Model Bundle:   {report['saved_path']}")
    print(f"Training Samples:     {report['training_sample_count']}")
    print(f"Feature Count:        {report['feature_count']}")
    print(f"Timestamp:            {report['trained_at']}")
    print("=" * 65)


if __name__ == "__main__":
    main()
