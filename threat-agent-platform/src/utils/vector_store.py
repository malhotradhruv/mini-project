"""Vector store manager for email threat classification and semantic search.

Wraps sentence-transformers (all-MiniLM-L6-v2) and faiss.IndexFlatL2 to provide
RAG and semantic similarity lookup against known phishing templates and benign communications.
Reference: IEEE Access (Hmimou et al., 2025).
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np

logger = logging.getLogger("VectorStoreManager")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class VectorStoreManager:
    """Manages text embeddings and FAISS index persistence for threat similarity matching."""

    EMBEDDING_DIM = 384  # Dimension for all-MiniLM-L6-v2

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """Initialize SentenceTransformer encoder and FAISS IndexFlatL2."""
        self.model_name = model_name
        self.model = None
        self.index = None
        self.texts: List[str] = []
        self.metadatas: List[Dict[str, Any]] = []

        self._init_encoder()
        self._init_faiss_index()

    def _init_encoder(self):
        """Lazy or immediate load of sentence-transformers encoder."""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            logger.info(f"Loaded SentenceTransformer: {self.model_name}")
        except Exception as e:
            logger.warning(
                f"SentenceTransformer initialization notice: {e}. "
                "Semantic embeddings will use fallback deterministic hashing if unavailable."
            )
            self.model = None

    def _init_faiss_index(self):
        """Initialize empty FAISS IndexFlatL2."""
        try:
            import faiss
            self.index = faiss.IndexFlatL2(self.EMBEDDING_DIM)
            logger.info(f"Initialized FAISS IndexFlatL2 with dimension {self.EMBEDDING_DIM}")
        except Exception as e:
            logger.warning(f"FAISS initialization notice: {e}. Running in lightweight vector mode.")
            self.index = None

    def _encode(self, texts: List[str]) -> np.ndarray:
        """Encode text batch into normalized float32 numpy vectors."""
        if not texts:
            return np.empty((0, self.EMBEDDING_DIM), dtype=np.float32)

        if self.model is not None:
            embeddings = self.model.encode(texts, convert_to_numpy=True, normalize_embeddings=True, show_progress_bar=False)
            return embeddings.astype(np.float32)

        # Deterministic pseudo-embedding fallback based on normalized character-ngram frequencies
        # Ensures tests and offline environments operate predictably without downloading large models
        vectors = []
        for t in texts:
            vec = np.zeros(self.EMBEDDING_DIM, dtype=np.float32)
            for idx, ch in enumerate(t.encode("utf-8", errors="ignore")):
                vec[(idx * 31 + ch) % self.EMBEDDING_DIM] += 1.0
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec = vec / norm
            vectors.append(vec)
        return np.array(vectors, dtype=np.float32)

    def add_texts(
        self,
        texts: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Add a list of text strings and optional metadata to the vector index.

        Args:
            texts: List of email or threat template texts to index.
            metadatas: Optional list of dictionary metadata records corresponding to texts.
        """
        if not texts:
            return

        embeddings = self._encode(texts)

        if self.index is not None:
            self.index.add(embeddings)

        self.texts.extend(texts)
        if metadatas and len(metadatas) == len(texts):
            self.metadatas.extend(metadatas)
        else:
            self.metadatas.extend([{"source": "unknown"} for _ in texts])

        logger.info(f"Indexed {len(texts)} items. Total vector store size: {len(self.texts)}")

    def search_similarity(
        self,
        query: str,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        """Search top-k most similar items to query string.

        Args:
            query: Input text to compare against index.
            top_k: Number of nearest neighbors to retrieve.

        Returns:
            List of dicts: [
                {
                    "text": str,
                    "metadata": dict,
                    "distance": float,
                    "similarity_score": float (0.0 to 1.0)
                }, ...
            ]
        """
        if not self.texts:
            return []

        k = min(top_k, len(self.texts))
        query_vec = self._encode([query])

        if self.index is not None and hasattr(self.index, "search"):
            distances, indices = self.index.search(query_vec, k)
            results = []
            for dist, idx in zip(distances[0], indices[0]):
                if idx < 0 or idx >= len(self.texts):
                    continue
                # Convert squared L2 distance between normalized unit vectors to cosine similarity
                sim = max(0.0, min(1.0, 1.0 - (float(dist) / 2.0)))
                results.append({
                    "text": self.texts[idx],
                    "metadata": self.metadatas[idx] if idx < len(self.metadatas) else {},
                    "distance": float(dist),
                    "similarity_score": round(sim, 4),
                })
            return results

        # Fallback in-memory L2 search
        store_vecs = self._encode(self.texts)
        dists = np.sum((store_vecs - query_vec[0]) ** 2, axis=1)
        top_indices = np.argsort(dists)[:k]
        results = []
        for idx in top_indices:
            dist = float(dists[idx])
            sim = max(0.0, min(1.0, 1.0 - (dist / 2.0)))
            results.append({
                "text": self.texts[idx],
                "metadata": self.metadatas[idx] if idx < len(self.metadatas) else {},
                "distance": dist,
                "similarity_score": round(sim, 4),
            })
        return results

    def save(self, path: Union[str, Path]) -> None:
        """Persist FAISS index and companion metadata to disk.

        Args:
            path: Target file path (e.g. data/indices/faiss_email_index.bin).
        """
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Save FAISS binary index
        if self.index is not None:
            try:
                import faiss
                faiss.write_index(self.index, str(file_path))
                logger.info(f"FAISS index written to {file_path}")
            except Exception as e:
                logger.warning(f"Error saving faiss index directly: {e}")

        # 2. Save companion metadata and texts
        meta_path = file_path.with_name(f"{file_path.name}.meta.json")
        payload = {
            "model_name": self.model_name,
            "dim": self.EMBEDDING_DIM,
            "count": len(self.texts),
            "texts": self.texts,
            "metadatas": self.metadatas,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        logger.info(f"Vector store metadata saved to {meta_path}")

    def load(self, path: Union[str, Path]) -> None:
        """Load FAISS index and companion metadata from disk.

        Args:
            path: Target file path to load (e.g. data/indices/faiss_email_index.bin).
        """
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Vector store index not found: {file_path}")

        # 1. Load companion metadata
        meta_path = file_path.with_name(f"{file_path.name}.meta.json")
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            self.texts = payload.get("texts", [])
            self.metadatas = payload.get("metadatas", [])
            self.model_name = payload.get("model_name", self.model_name)
            logger.info(f"Loaded {len(self.texts)} items from metadata at {meta_path}")
        else:
            logger.warning(f"Companion metadata not found at {meta_path}")

        # 2. Load FAISS index
        try:
            import faiss
            self.index = faiss.read_index(str(file_path))
            logger.info(f"Loaded FAISS binary index from {file_path}")
        except Exception as e:
            logger.warning(f"Notice loading FAISS index: {e}. Rebuilding index from stored texts.")
            self._init_faiss_index()
            if self.texts:
                embeddings = self._encode(self.texts)
                if self.index is not None:
                    self.index.add(embeddings)
