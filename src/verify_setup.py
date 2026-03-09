import pandas as pd
import numpy as np
import sklearn
from sentence_transformers import SentenceTransformer

print("✅ Pandas:", pd.__version__)
print("✅ NumPy:", np.__version__)
print("✅ Scikit-learn:", sklearn.__version__)

# Test embedding model download
print("\n⏳ Loading embedding model...")
model = SentenceTransformer('all-MiniLM-L6-v2')
test = model.encode(["test connection"])
print("✅ Embedding model working!")
