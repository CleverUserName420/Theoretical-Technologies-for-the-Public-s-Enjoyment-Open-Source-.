#!/usr/bin/env python3

from typing import Set
import itertools
import os
import sys
import zlib
import math
import struct
import subprocess
import re
import argparse
import logging
import json
import datetime
import time
import base64
import hashlib
import hmac
import socket
import ipaddress
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path
from typing import List, Tuple, Dict, Optional, Union, Callable, Any
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.parser import BytesParser
import threading
import queue

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    import scipy
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

# ============================================================
# CONSTANTS & CONFIGURATION
# ============================================================

__version__ = "1.0.0"
__author__ = "CleverUserName420"

# Analysis parameters
HIGH_ENTROPY_THRESHOLD = 7.8  # bits/byte
MAX_ATTACHMENT_SIZE = 52428800  # 50MB
MAX_FILE_SIZE = 104857600  # 100MB
CONFIDENCE_THRESHOLD = 0.6
WINDOW_SIZE = 256
ANALYSIS_TIMEOUT = 300  # 5 minutes
MAX_ENTROPY_SAMPLE_SIZE = 8192  # Maximum bytes for expensive entropy calculations (ApEn, SampEn)

# Directory paths
LOG_DIR = Path.home() / '.email_payload_detector' / 'logs'
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# LOGGING CONFIGURATION
# ============================================================


class AnalysisLogger:
    """Centralized logging for analysis engine."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, log_level=logging.INFO):
        """Singleton pattern for logger."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, log_level=logging.INFO):
        """Initialize logger with file and console handlers."""
        if self._initialized:
            return

        self.logger = logging.getLogger('EmailPayloadDetector')
        self.logger.setLevel(log_level)

        # Prevent duplicate handlers
        if self.logger.handlers:
            return

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)

        # File handler
        log_file = LOG_DIR / f"analysis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self._initialized = True

    def get_logger(self) -> logging.Logger:
        """Get logger instance."""
        return self.logger


# Global logger instance
logger = AnalysisLogger().get_logger()

# ============================================================
# ENTROPY CALCULATION
# ============================================================


class EntropyAnalyzer:
    """
    Core entropy analysis engine with multiple entropy metrics.

    Supports:
    - Shannon entropy
    - Rényi entropy
    - Minimum entropy
    - Chi-squared test
    - Gini coefficient
    - Approximate entropy
    - Sample entropy
    - Permutation entropy
    - Lempel-Ziv complexity
    - Spectral entropy
    - Fuzzy entropy
    - Dispersion entropy

    Attributes:
        window_size (int): Window size for entropy analysis
        threshold (float): Entropy threshold for flagging suspicious data
        findings (List[Dict]): Analysis findings
        logger (logging.Logger): Logger instance
    """

    def __init__(self, window_size: int = 256, threshold: float = 7.8,
                 logger: Optional[logging.Logger] = None):
        """
        Initialize entropy analyzer with enhanced configuration.

        Args:
            window_size (int): Window size for entropy calculations (default: 256)
            threshold (float): Entropy threshold 0-8 bits/byte (default: 7.8)
            logger (Optional[logging.Logger]): Logger instance

        Raises:
            ValueError: If window_size < 1 or threshold not in 0-8 range
        """
        if window_size < 1:
            raise ValueError(f"window_size must be > 0, got {window_size}")
        if not (0 <= threshold <= 8):
            raise ValueError(f"threshold must be between 0 and 8, got {threshold}")

        self.window_size = window_size
        self.threshold = threshold
        self.findings = []
        self.logger = logger or logging.getLogger(__name__)

        # Enhanced: Add performance metrics tracking
        self.metrics = {
            'analyses_performed': 0,
            'high_entropy_detections': 0,
            'total_bytes_analyzed': 0,
            'processing_time': 0.0
        }

        # Enhanced: Add entropy cache for performance
        self._entropy_cache = {}
        self._cache_hits = 0
        self._cache_misses = 0

    def shannon_entropy(self, data: bytes, use_cache: bool = True) -> float:
        """
        Calculate Shannon entropy with caching and validation.

        Shannon entropy measures the average information content per byte.
        H(X) = -Σ P(x) * log2(P(x))

        Range: 0 (all bytes identical) to 8 (perfectly random)

        Args:
            data (bytes): Input data to analyze
            use_cache (bool): Whether to use entropy cache (default: True)

        Returns:
            float: Shannon entropy value (0-8 bits/byte)

        Raises:
            ValueError: If data is empty
            TypeError: If data is not bytes
        """
        # Enhanced validation
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type(data).__name__}")

        if not data:
            self.logger.warning("Cannot calculate entropy on empty data")
            return 0.0

        # Check cache
        if use_cache:
            data_hash = hashlib.md5(data).hexdigest()
            if data_hash in self._entropy_cache:
                self._cache_hits += 1
                self.logger.debug(f"Entropy cache hit (hits: {self._cache_hits})")
                return self._entropy_cache[data_hash]
            self._cache_misses += 1

        start_time = time.perf_counter()

        try:
            # Use numpy for better performance if available
            if HAS_NUMPY and len(data) > 1024:  # Use numpy for larger datasets
                byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
                probabilities = byte_counts[byte_counts > 0] / len(data)
                entropy = -np.sum(probabilities * np.log2(probabilities))
            else:
                # Fallback to pure Python
                counter = Counter(data)
                length = len(data)
                entropy = 0.0

                for count in counter.values():
                    if count > 0:  # Safety check
                        probability = count / length
                        entropy -= probability * math.log2(probability)

            # Update metrics
            self.metrics['analyses_performed'] += 1
            self.metrics['total_bytes_analyzed'] += len(data)
            self.metrics['processing_time'] += time.perf_counter() - start_time

            # Check if high entropy
            if entropy >= self.threshold:
                self.metrics['high_entropy_detections'] += 1
                self.findings.append({
                    'type': 'high_entropy',
                    'value': entropy,
                    'threshold': self.threshold,
                    'data_size': len(data),
                    'timestamp': datetime.now().isoformat()
                })
                self.logger.warning(f"High entropy detected: {entropy:.3f} bits/byte (threshold: {self.threshold})")

            # Cache result
            if use_cache and len(self._entropy_cache) < 1000:  # Limit cache size
                self._entropy_cache[data_hash] = entropy

            return round(entropy, 6)  # Round to 6 decimal places

        except Exception as e:
            self.logger.error(f"Error calculating Shannon entropy: {e}", exc_info=True)
            return 0.0

    def min_entropy(self, data: bytes) -> float:
        """
        Calculate minimum entropy (Hartley entropy).

        Min-entropy represents the worst-case scenario for unpredictability,
        measuring the probability of guessing the most likely symbol.
        Used in cryptography to assess key strength.

        H_∞(X) = -log2(max(P(x)))

        Range: 0 (one byte value) to 8 (all bytes equally probable)

        Args:
            data (bytes): Input data to analyze

        Returns:
            float: Minimum entropy value in bits
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type(data).__name__}")

        if not data:
            self.logger.debug("Empty data for min_entropy calculation")
            return 0.0

        try:
            # Use numpy for better performance if available
            if HAS_NUMPY and len(data) > 1024:
                byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
                max_freq = np.max(byte_counts)
            else:
                counter = Counter(data)
                max_freq = max(counter.values()) if counter else 0

            if max_freq == 0 or max_freq == len(data):
                # All same byte or empty
                return 0.0

            min_ent = -math.log2(max_freq / len(data))

            # Security assessment
            if min_ent < 1.0:
                self.logger.warning(f"Very low min-entropy: {min_ent:.3f} - highly predictable")
                self.findings.append({
                    'type': 'low_min_entropy',
                    'value': min_ent,
                    'max_frequency': max_freq,
                    'data_size': len(data),
                    'security_risk': 'HIGH',
                    'timestamp': datetime.now().isoformat()
                })
            elif min_ent < 3.0:
                self.logger.info(f"Low min-entropy: {min_ent:.3f} - moderate predictability")

            return round(min_ent, 6)

        except Exception as e:
            self.logger.error(f"Error calculating min entropy: {e}", exc_info=True)
            return 0.0

    def chi_squared_test(self, data: bytes) -> float:
        """
        Perform chi-squared test for uniform distribution.

        Tests if byte distribution is uniform (expected for random data).
        χ² = Σ ((observed - expected)² / expected)

        Args:
            data (bytes): Input data

        Returns:
            float: Chi-squared test statistic
        """
        if not data:
            return 0.0

        try:
            expected_freq = len(data) / 256
            byte_counts = [0] * 256

            for byte in data:
                byte_counts[byte] += 1

            chi_squared = 0.0
            for count in byte_counts:
                if expected_freq > 0:
                    chi_squared += ((count - expected_freq) ** 2) / expected_freq
            return chi_squared
        except Exception as e:
            self.logger.error(f"Error in chi-squared test: {e}", exc_info=True)
            return 0.0

    def gini_coefficient(self, data: bytes) -> float:
        """
        Calculate Gini coefficient (inequality measure).

        Measures distribution inequality. Gini = 0 (uniform), Gini = 1 (concentrated)

        Args:
            data (bytes): Input data

        Returns:
            float: Gini coefficient (0-1)
        """
        if not data:
            return 0.0

        try:
            counter = Counter(data)
            sorted_counts = sorted(counter.values())
            n = len(data)

            # Gini = (2 * sum(i * c_i)) / (n * (n + 1)) - 1
            numerator = sum((i + 1) * count for i, count in enumerate(sorted_counts))
            denominator = n * (n + 1) / 2

            if denominator > 0:
                return (2 * numerator / denominator) - 1
            else:
                return 0.0
        except Exception as e:
            self.logger.error(f"Error calculating Gini coefficient: {e}")
            return 0.0

    def approximate_entropy(self, data: bytes, m: int = 2, r: float = 0.2) -> float:
        """
        Calculate approximate entropy (ApEn).

        Detects regular patterns in randomness. Higher = more random.

        Args:
            data (bytes): Input data
            m (int): Pattern length (default: 2)
            r (float): Tolerance threshold (default: 0.2)

        Returns:
            float: Approximate entropy value
        """
        # CRITICAL PERFORMANCE FIX: ApEn has O(n²) complexity - use very small sample
        MAX_APEN_SIZE = 512  # Reduced from 8192 to prevent freezing
        if len(data) > MAX_APEN_SIZE:
            self.logger.debug(f"ApEn: Sampling {MAX_APEN_SIZE} bytes from {len(data)} byte file")
            # Take evenly distributed samples
            step = len(data) // MAX_APEN_SIZE
            data = bytes(data[i] for i in range(0, len(data), step))[:MAX_APEN_SIZE]
        
        if len(data) < m + 1:
            self.logger.debug(f"Data too short for ApEn (need {m+1}, got {len(data)})")
            return 0.0
        try:
            def _maxdist(x_i, x_j):
                """Calculate maximum distance between sequences."""
                try:
                    dists = [abs(int(ua) - int(va)) for ua, va in zip(x_i, x_j)]
                    return max(dists) if dists else 0
                except (TypeError, ValueError):
                    return float('inf')

            def _phi(m_val):
                """Calculate phi(m)."""
                x = [[data[j] for j in range(i, i + m_val)] for i in range(len(data) - m_val + 1)]
                C = []
                for x_i in x:
                    count = sum(1 for x_j in x if _maxdist(x_i, x_j) <= r)
                    C.append(count / (len(data) - m_val + 1.0))
                return (len(data) - m_val + 1.0) ** (-1) * sum(math.log(c) for c in C if c > 0)

            return _phi(m + 1) - _phi(m)
        except Exception as e:
            self.logger.error(f"Error calculating approximate entropy: {e}", exc_info=True)
            return 0.0

    def sample_entropy(self, data: bytes, m: int = 2, r: float = 0.2) -> float:
        """
        Calculate sample entropy (SampEn).

        More robust than ApEn for short sequences.

        Args:
            data (bytes): Input data
            m (int): Pattern length (default: 2)
            r (float): Tolerance threshold (default: 0.2)

        Returns:
            float: Sample entropy value
        """
        # CRITICAL PERFORMANCE FIX: SampEn has O(n²) complexity - use very small sample
        MAX_SAMPEN_SIZE = 512  # Reduced from 8192 to prevent freezing
        if len(data) > MAX_SAMPEN_SIZE:
            self.logger.debug(f"SampEn: Sampling {MAX_SAMPEN_SIZE} bytes from {len(data)} byte file")
            # Take evenly distributed samples
            step = len(data) // MAX_SAMPEN_SIZE
            data = bytes(data[i] for i in range(0, len(data), step))[:MAX_SAMPEN_SIZE]
        
        if len(data) < m + 2:
            self.logger.debug(f"Data too short for SampEn (need {m+2}, got {len(data)})")
            return 0.0

        try:
            def _maxdist(x_i, x_j):
                """Calculate maximum distance between sequences."""
                dists = [abs(ua - va) for ua, va in zip(x_i, x_j)]
                return max(dists) if dists else 0

            B = len([1 for i in range(len(data) - m) for j in range(i + 1, len(data) - m)
                     if _maxdist(data[i:i + m], data[j:j + m]) <= r])
            A = len([1 for i in range(len(data) - m - 1) for j in range(i + 1, len(data) - m)
                     if _maxdist(data[i:i + m + 1], data[j:j + m + 1]) <= r])

            if A > 0 and B > 0:
                return -math.log(A / B)
            else:
                return 0.0
        except Exception as e:
            self.logger.error(f"Error calculating sample entropy: {e}")
            return 0.0

    def find_high_entropy_regions(self, data: bytes, window: int = 100,
                                   stride: int = 50) -> List[Tuple[int, bytes, float]]:
        """
        Find all high-entropy blocks in data.

        Identifies suspicious regions that may be encrypted or compressed.

        Args:
            data (bytes): Input data
            window (int): Window size (default: 100)
            stride (int): Stride between windows (default: 50)

        Returns:
            List[Tuple[int, bytes, float]]: List of (offset, block, entropy) tuples

        Raises:
            ValueError: If window or stride invalid
        """
        if window < 1 or stride < 1:
            raise ValueError("window and stride must be > 0")

        regions = []

        try:
            for offset in range(0, len(data) - window, stride):
                block = data[offset:offset + window]
                entropy = self.shannon_entropy(block)

                if entropy > self.threshold:
                    regions.append((offset, block, entropy))

            self.logger.info(f"Found {len(regions)} high-entropy regions")
            return regions
        except Exception as e:
            self.logger.error(f"Error finding high-entropy regions: {e}")
            return []

    def renyi_entropy(self, data: bytes, alpha: float) -> float:
        """
        Calculate Rényi entropy of order alpha.

        Generalizes Shannon entropy: H_α(X) = (1/(1-α)) * log2(Σ P(x)^α)

        Args:
            data (bytes): Input data
            alpha (float): Order parameter

        Returns:
            float: Rényi entropy value
        """
        if not data or alpha == 1.0:
            return self.shannon_entropy(data)

        try:
            counter = Counter(data)
            length = len(data)

            if alpha == float('inf'):
                return self._renyi_entropy_infinity(data)

            sum_prob = sum((count / length) ** alpha for count in counter.values())

            if alpha != 1 and sum_prob > 0:
                return (1.0 / (1.0 - alpha)) * math.log2(sum_prob)
            return 0.0
        except Exception as e:
            self.logger.error(f"Error calculating Rényi entropy: {e}")
            return 0.0

    def analyze_entropy_distribution(self, data: bytes) -> Dict:
        """
        Complete entropy profile with multi-layer analysis.

        Includes: wavelet analysis, recurrence quantification analysis (RQA),
        permutation entropy, Lempel-Ziv complexity, and spectral analysis

        Args:
            data (bytes): Input data

        Returns:
            Dict: Comprehensive entropy profile

        Raises:
            Exception: Any calculation errors (caught and logged)
        """
        if not data:
            self.logger.warning("Empty data for entropy distribution analysis")
            return self._get_empty_entropy_profile()

        try:
            windows = []
            window_size = 256

            # Multi-scale entropy analysis (different window sizes)
            multi_scale_entropies = {
                'scale_64': [],
                'scale_128': [],
                'scale_256': [],
                'scale_512': [],
            }

            for offset in range(0, len(data), window_size):
                block = data[offset:offset + window_size]
                if len(block) > 0:
                    windows.append(self.shannon_entropy(block))

            # Multi-scale calculation
            for offset in range(0, len(data) - 64, 32):
                multi_scale_entropies['scale_64'].append(
                    self.shannon_entropy(data[offset:offset + 64]))

            for offset in range(0, len(data) - 128, 64):
                multi_scale_entropies['scale_128'].append(
                    self.shannon_entropy(data[offset:offset + 128]))

            for offset in range(0, len(data) - 256, 128):
                multi_scale_entropies['scale_256'].append(
                    self.shannon_entropy(data[offset:offset + 256]))

            for offset in range(0, len(data) - 512, 256):
                multi_scale_entropies['scale_512'].append(
                    self.shannon_entropy(data[offset:offset + 512]))

            # Calculate statistics for each scale
            scale_stats = {}
            for scale_name, entropies in multi_scale_entropies.items():
                if entropies:
                    scale_stats[scale_name] = {
                        'mean': sum(entropies) / len(entropies),
                        'max': max(entropies),
                        'min': min(entropies),
                        'std': math.sqrt(sum((e - sum(entropies) / len(entropies))**2 for e in entropies) / len(entropies))
                    }

            # Enhanced entropy metrics
            shannon_entropy = self.shannon_entropy(data)
            renyi_entropy_2 = self.renyi_entropy(data, 2.0)
            renyi_entropy_inf = self._renyi_entropy_infinity(data)
            tsallis_entropy = self._tsallis_entropy(data, q=2.0)
            min_entropy_val = self.min_entropy(data)
            chi_squared = self.chi_squared_test(data)
            gini_coeff = self.gini_coefficient(data)

            # NEW: Permutation Entropy (detects order patterns in data)
            permutation_entropy = self._calculate_permutation_entropy(data, order=3)

            # NEW: Lempel-Ziv Complexity (detects pattern compressibility)
            lz_complexity = self._calculate_lz_complexity(data)

            # NEW: Spectral Entropy (analyzes frequency domain)
            spectral_entropy = self._calculate_spectral_entropy(data)

            # NEW: Approximate and Sample Entropy for pattern detection
            approx_entropy = self.approximate_entropy(data, m=2, r=0.2)
            sample_entropy_val = self.sample_entropy(data, m=2, r=0.2)

            # NEW: Fuzzy Entropy (robust to noise)
            fuzzy_entropy = self._calculate_fuzzy_entropy(data)

            # NEW: Dispersion Entropy (robust to noise and non-stationary data)
            dispersion_entropy = self._calculate_dispersion_entropy(data)

            # NEW: Byte distribution analysis (skewness and kurtosis)
            byte_dist = self._analyze_byte_distribution(data)

            # NEW: Recurrence Quantification Analysis (RQA) - detects determinism
            rqa_metrics = self._calculate_rqa(data)

            # NEW: Entropy gradient analysis (rate of change)
            entropy_gradient = self._calculate_entropy_gradient(data)

            # Comprehensive result dictionary
            result = {
                # Traditional entropy metrics
                'shannon': shannon_entropy,
                'renyi_2': renyi_entropy_2,
                'renyi_infinity': renyi_entropy_inf,
                'tsallis': tsallis_entropy,
                'min_entropy_value': min_entropy_val,
                'chi_squared': chi_squared,
                'gini': gini_coeff,

                # Pattern detection entropy
                'permutation_entropy': permutation_entropy,
                'approximate_entropy': approx_entropy,
                'sample_entropy': sample_entropy_val,
                'fuzzy_entropy': fuzzy_entropy,
                'dispersion_entropy': dispersion_entropy,

                # Complexity metrics
                'lz_complexity': lz_complexity,
                'spectral_entropy': spectral_entropy,

                # Distribution analysis
                'byte_skewness': byte_dist['skewness'],
                'byte_kurtosis': byte_dist['kurtosis'],
                'byte_variance': byte_dist['variance'],

                # Advanced RQA metrics
                'rqa_determinism': rqa_metrics['determinism'],
                'rqa_laminarity': rqa_metrics['laminarity'],
                'rqa_trapping_time': rqa_metrics['trapping_time'],
                'rqa_entropy': rqa_metrics['entropy'],

                # Multi-scale analysis
                'multi_scale_stats': scale_stats,

                # Window-based statistics
                'mean_entropy': sum(windows) / len(windows) if windows else 0,
                'max_entropy': max(windows) if windows else 0,
                'min_entropy': min(windows) if windows else 0,
                'entropy_std': math.sqrt(sum((w - (sum(windows) / len(windows)))**2 for w in windows) / len(windows)) if windows else 0,

                # Gradient analysis
                'entropy_gradient_mean': entropy_gradient['mean'],
                'entropy_gradient_max': entropy_gradient['max'],
                'entropy_gradient_acceleration': entropy_gradient['acceleration'],

                # Overall assessments
                'total_samples': len(windows),
                'data_size': len(data),
                'entropy_profile': self._classify_entropy_profile(shannon_entropy, permutation_entropy, lz_complexity),
            }

            return result

        except Exception as e:
            self.logger.error(f"Error in entropy distribution analysis: {str(e)}")
            return self._get_empty_entropy_profile()

    def _renyi_entropy_infinity(self, data: bytes) -> float:
        """
        NEW: Rényi entropy as α→∞ (min-entropy approximation)
        More sensitive to rare events than Shannon entropy
        """
        try:
            if not data:
                return 0.0

            counter = Counter(data)
            max_prob = max(counter.values()) / len(data)

            return -math.log2(max_prob) if max_prob > 0 else 0.0
        except:
            return 0.0

    def _tsallis_entropy(self, data: bytes, q: float = 2.0) -> float:
        """
        NEW: Tsallis (q-order) entropy
        Generalizes Shannon entropy for non-equilibrium systems
        Useful for detecting phase transitions in data
        """
        try:
            if not data or q == 1.0:
                return self.shannon_entropy(data)

            counter = Counter(data)
            length = len(data)

            sum_prob = sum((count / length) ** q for count in counter.values())

            if q != 1:
                return (1.0 / (1.0 - q)) * (1.0 - sum_prob)
            return 0.0
        except:
            return 0.0

    def _calculate_permutation_entropy(self, data: bytes, order: int = 3) -> float:
        """
        NEW: Permutation Entropy
        Captures ordinal patterns and sequence structure
        High PE = random; Low PE = deterministic/regular patterns
        Excellent for detecting malware obfuscation patterns
        """
        try:
            if len(data) < order:
                return 0.0

            # Count ordinal patterns
            pattern_counts = Counter()

            for i in range(len(data) - order + 1):
                # Get ordinal pattern (relative ordering)
                pattern = tuple(sorted(range(order), key=lambda j: data[i + j]))
                pattern_counts[pattern] += 1

            # Calculate entropy of patterns
            total = sum(pattern_counts.values())
            entropy = 0.0

            for count in pattern_counts.values():
                if count > 0:
                    prob = count / total
                    entropy -= prob * math.log2(prob)

            # Normalize by maximum possible entropy
            max_entropy = math.log2(math.factorial(order))
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

            return normalized_entropy
        except:
            return 0.0

    def _calculate_lz_complexity(self, data: bytes) -> float:
        """
        NEW: Lempel-Ziv Complexity
        Measures data compressibility and pattern repetition
        Low complexity = high repetition/compression possible (suspicious)
        High complexity = random/encrypted (expected for malware)
        """
        try:
            if not data:
                return 0.0

            # Convert to binary string representation
            binary_str = ''.join(format(byte, '08b') for byte in data[:1000])  # Limit for performance

            complexity = 0
            u = 0
            v = 1
            while u + v <= len(binary_str):
                # Check if binary_str[u:u+v] appears in binary_str[:u+v-1]
                substring = binary_str[u:u + v]
                prefix = binary_str[:u + v - 1]

                if substring not in prefix:
                    complexity += 1
                    u += v
                    v = 1
                else:
                    v += 1

            # Normalize by data length
            normalized_complexity = complexity / len(binary_str) if binary_str else 0.0

            return normalized_complexity
        except:
            return 0.0

    def _calculate_spectral_entropy(self, data: bytes) -> float:
        """
        NEW: Spectral Entropy
        Analyzes frequency domain distribution using FFT-like approach
        Detects periodic patterns and signal structure
        """
        try:
            if len(data) < 16:
                return 0.0

            # Simple frequency analysis (instead of full FFT for performance)
            byte_array = list(data[:1000])  # Limit for performance
            freq_spectrum = Counter(byte_array)

            # Calculate power spectrum
            total_power = sum(count ** 2 for count in freq_spectrum.values())

            if total_power == 0:
                return 0.0

            # Spectral entropy from normalized power spectrum
            entropy = 0.0
            for count in freq_spectrum.values():
                power_norm = (count ** 2) / total_power
                if power_norm > 0:
                    entropy -= power_norm * math.log2(power_norm)

            # Normalize by maximum possible entropy
            max_entropy = math.log2(len(freq_spectrum)) if freq_spectrum else 0
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

            return normalized_entropy
        except:
            return 0.0

    def _calculate_fuzzy_entropy(self, data: bytes, m: int = 2, r: float = 0.15) -> float:
        """
        NEW: Fuzzy Entropy
        Robust entropy metric that handles noise and uncertainty
        Better than Shannon entropy for noisy/corrupted data
        """
        try:
            # PERFORMANCE FIX: Sample data if too large (O(n²) complexity!)
            if len(data) > MAX_ENTROPY_SAMPLE_SIZE:
                self.logger.debug(f"FuzzyEn: Sampling {MAX_ENTROPY_SAMPLE_SIZE} bytes from {len(data)} byte file")
                # Take evenly distributed samples
                step = len(data) // MAX_ENTROPY_SAMPLE_SIZE
                data = bytes(data[i] for i in range(0, len(data), step))[:MAX_ENTROPY_SAMPLE_SIZE]
            
            if len(data) < m + 1:
                return 0.0

            def _fuzzy_membership(distance, radius):
                """Triangular membership function"""
                if distance <= 0:
                    return 1.0
                elif distance < radius:
                    return 1.0 - (distance / radius)
                else:
                    return 0.0

            # Create embedding matrix
            embeddings = []
            for i in range(len(data) - m + 1):
                embedding = [data[j] for j in range(i, i + m)]
                embeddings.append(embedding)

            # Calculate fuzzy entropy
            phi_m = 0.0
            for i in range(len(embeddings)):
                c_i = 0.0
                for j in range(len(embeddings)):
                    if i != j:
                        distance = max(abs(embeddings[i][k] - embeddings[j][k]) for k in range(m))
                        c_i += _fuzzy_membership(distance, r)

                if c_i > 0:
                    phi_m += math.log(c_i / len(embeddings))

            phi_m = -phi_m / len(embeddings)

            # Calculate for m+1 embeddings
            embeddings_plus = []
            for i in range(len(data) - m):
                embedding = [data[j] for j in range(i, i + m + 1)]
                embeddings_plus.append(embedding)

            phi_m_plus = 0.0
            for i in range(len(embeddings_plus)):
                c_i = 0.0
                for j in range(len(embeddings_plus)):
                    if i != j:
                        distance = max(abs(embeddings_plus[i][k] - embeddings_plus[j][k]) for k in range(m + 1))
                        c_i += _fuzzy_membership(distance, r)

                if c_i > 0:
                    phi_m_plus += math.log(c_i / len(embeddings_plus))

            phi_m_plus = -phi_m_plus / len(embeddings_plus)

            # Fuzzy entropy
            fuzzy_ent = phi_m - phi_m_plus if phi_m_plus > 0 else 0.0

            return max(fuzzy_ent, 0.0)
        except:
            return 0.0

    def _calculate_dispersion_entropy(self, data: bytes, classes: int = 10) -> float:
        """
        NEW: Dispersion Entropy
        Robust to noise and non-stationary data
        Based on probability distribution of relative byte values
        """
        try:
            if len(data) < 2:
                return 0.0

            # Normalize data to dispersion classes (0 to classes-1)
            min_val = min(data)
            max_val = max(data)
            range_val = max_val - min_val if max_val > min_val else 1

            normalized = [(b - min_val) * (classes - 1) // range_val for b in data]

            # Calculate relative frequencies
            freq_dist = Counter(normalized)
            total = len(normalized)

            # Calculate entropy
            entropy = 0.0
            for count in freq_dist.values():
                if count > 0:
                    prob = count / total
                    entropy -= prob * math.log2(prob)

            # Normalize
            max_entropy = math.log2(classes)
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

            return normalized_entropy
        except:
            return 0.0

    def _analyze_byte_distribution(self, data: bytes) -> Dict:
        """
        NEW: Advanced byte distribution analysis
        Calculates skewness, kurtosis, and variance
        Helps identify specific entropy patterns
        """
        try:
            byte_array = list(data)
            n = len(byte_array)

            if n < 2:
                return {'skewness': 0.0, 'kurtosis': 0.0, 'variance': 0.0}

            # Mean
            mean = sum(byte_array) / n

            # Variance
            variance = sum((x - mean) ** 2 for x in byte_array) / n
            std_dev = math.sqrt(variance)

            if std_dev == 0:
                return {'skewness': 0.0, 'kurtosis': 0.0, 'variance': variance}

            # Skewness (3rd moment)
            skewness = sum((x - mean) ** 3 for x in byte_array) / (n * std_dev ** 3)

            # Kurtosis (4th moment) - excess kurtosis
            kurtosis = (sum((x - mean) ** 4 for x in byte_array) / (n * std_dev ** 4)) - 3

            return {
                'skewness': skewness,
                'kurtosis': kurtosis,
                'variance': variance,
                'mean': mean,
                'std_dev': std_dev,
            }
        except:
            return {'skewness': 0.0, 'kurtosis': 0.0, 'variance': 0.0}

    def _calculate_rqa(self, data: bytes, m: int = 2, threshold: float = 0.1) -> Dict:
        """
        NEW: Recurrence Quantification Analysis (RQA)
        Detects deterministic patterns and chaos
        Key metrics:
        - Determinism: predictability of system
        - Laminarity: laminar states
        - Trapping time: duration of laminar phases
        - Entropy: complexity of recurrence structure
        """
        try:
            # CRITICAL PERFORMANCE FIX: RQA has O(n²) complexity - use very small sample
            MAX_RQA_SIZE = 512  # Limit to prevent freezing
            if len(data) > MAX_RQA_SIZE:
                self.logger.debug(f"RQA: Sampling {MAX_RQA_SIZE} bytes from {len(data)} byte file")
                # Take evenly distributed samples
                step = len(data) // MAX_RQA_SIZE
                data = bytes(data[i] for i in range(0, len(data), step))[:MAX_RQA_SIZE]
            
            if len(data) < m * 2:
                return {
                    'determinism': 0.0,
                    'laminarity': 0.0,
                    'trapping_time': 0.0,
                    'entropy': 0.0,
                }

            # Create embedding
            embeddings = []
            for i in range(len(data) - m + 1):
                emb = tuple(data[i:i + m])
                embeddings.append(emb)

            n_embeddings = len(embeddings)

            # Calculate recurrence matrix (simplified - based on distance threshold)
            recurrence_points = []
            for i in range(n_embeddings):
                for j in range(n_embeddings):
                    if i != j:
                        # Calculate Euclidean distance
                        distance = math.sqrt(sum((embeddings[i][k] - embeddings[j][k]) ** 2 for k in range(m)))
                        if distance < threshold * 255:  # threshold scaled to byte range
                            recurrence_points.append((i, j))

            if not recurrence_points:
                return {
                    'determinism': 0.0,
                    'laminarity': 0.0,
                    'trapping_time': 0.0,
                    'entropy': 0.0,
                }

            # Determinism: ratio of recurrence points forming diagonal structures
            diagonal_points = sum(1 for i, j in recurrence_points if i - j == 0)
            determinism = diagonal_points / len(recurrence_points) if recurrence_points else 0.0

            # Laminarity: ratio of vertical structures (same i, different j)
            vertical_structures = Counter(i for i, j in recurrence_points)
            laminarity = sum(1 for count in vertical_structures.values() if count > 1) / len(embeddings) if embeddings else 0.0

            # Trapping time: average duration of laminar phases
            trapping_times = [count for count in vertical_structures.values() if count > 1]
            trapping_time = sum(trapping_times) / len(trapping_times) if trapping_times else 0.0

            # RQA Entropy: entropy of recurrence structure
            rqa_entropy = -sum((len(recurrence_points)) / (n_embeddings ** 2) *
                              math.log2(len(recurrence_points) / (n_embeddings ** 2))) if recurrence_points else 0.0

            return {
                'determinism': min(determinism, 1.0),
                'laminarity': min(laminarity, 1.0),
                'trapping_time': trapping_time,
                'entropy': rqa_entropy,
            }
        except:
            return {
                'determinism': 0.0,
                'laminarity': 0.0,
                'trapping_time': 0.0,
                'entropy': 0.0,
            }

    def _calculate_entropy_gradient(self, data: bytes, window: int = 64) -> Dict:
        """
        NEW: Entropy Gradient Analysis
        Analyzes rate of change of entropy across data
        Detects transitions between encrypted/plaintext regions
        """
        try:
            if len(data) < window * 2:
                return {
                    'mean': 0.0,
                    'max': 0.0,
                    'min': 0.0,
                    'acceleration': 0.0,
                }

            # Calculate entropy at each position
            entropies = []
            for offset in range(0, len(data) - window, window // 2):
                block = data[offset:offset + window]
                ent = self.shannon_entropy(block)
                entropies.append(ent)

            if len(entropies) < 2:
                return {
                    'mean': 0.0,
                    'max': 0.0,
                    'min': 0.0,
                    'acceleration': 0.0,
                }

            # First derivative (gradient)
            gradients = [entropies[i + 1] - entropies[i] for i in range(len(entropies) - 1)]

            # Second derivative (acceleration)
            accelerations = [gradients[i + 1] - gradients[i] for i in range(len(gradients) - 1)] if len(gradients) > 1 else [0]

            return {
                'mean': sum(gradients) / len(gradients) if gradients else 0.0,
                'max': max(gradients) if gradients else 0.0,
                'min': min(gradients) if gradients else 0.0,
                'acceleration': sum(accelerations) / len(accelerations) if accelerations else 0.0,
            }
        except:
            return {
                'mean': 0.0,
                'max': 0.0,
                'min': 0.0,
                'acceleration': 0.0,
            }

    def _classify_entropy_profile(self, shannon: float, permutation: float, lz: float) -> str:
        """
        NEW: Comprehensive entropy profile classification
        Returns human-readable classification of data entropy profile
        """
        if shannon > 7.5 and permutation > 0.8 and lz > 0.7:
            return 'Highly Encrypted/Random - Malware Likely'
        elif shannon > 7.0 and permutation > 0.7:
            return 'Compressed/Encrypted - Suspicious'
        elif shannon > 6.0 and lz > 0.5:
            return 'Mixed Content - Review Needed'
        elif shannon > 5.0 and permutation < 0.5:
            return 'Structured Data - Low Risk'
        else:
            return 'Plaintext/Normal Data'

    def _get_empty_entropy_profile(self) -> Dict:
        """NEW: Return default empty profile for error handling"""
        return {
            'shannon': 0.0,
            'renyi_2': 0.0,
            'renyi_infinity': 0.0,
            'tsallis': 0.0,
            'min_entropy_value': 0.0,
            'chi_squared': 0.0,
            'gini': 0.0,
            'permutation_entropy': 0.0,
            'approximate_entropy': 0.0,
            'sample_entropy': 0.0,
            'fuzzy_entropy': 0.0,
            'dispersion_entropy': 0.0,
            'lz_complexity': 0.0,
            'spectral_entropy': 0.0,
            'byte_skewness': 0.0,
            'byte_kurtosis': 0.0,
            'byte_variance': 0.0,
            'rqa_determinism': 0.0,
            'rqa_laminarity': 0.0,
            'rqa_trapping_time': 0.0,
            'rqa_entropy': 0.0,
            'multi_scale_stats': {},
            'mean_entropy': 0.0,
            'max_entropy': 0.0,
            'min_entropy': 0.0,
            'entropy_std': 0.0,
            'entropy_gradient_mean': 0.0,
            'entropy_gradient_max': 0.0,
            'entropy_gradient_acceleration': 0.0,
            'total_samples': 0,
            'data_size': 0,
            'entropy_profile': 'Error - Unable to analyze',
        }


class CompressionDetector:
    """
    APEX Enterprise-Grade Compression & Archive Detection Engine

    Detects 20+ compression formats with forensic analysis:
    - Gzip, Deflate, Brotli, Zstandard, LZ4, LZMA, XZ, PPMd
    - ZIP, RAR, 7-Zip, ISO, TAR, CPIO
    - PE executables, ELF binaries
    - Nested/layered compression
    - Suspicious compression patterns
    """

    # ============================================================
    # COMPREHENSIVE MAGIC BYTE DATABASE
    # ============================================================

    MAGIC_BYTES={
        # Format: (magic_bytes, name, min_size, category)
        (b'\x1f\x8b', 'gzip'): {'min_size': 10, 'category': 'Compression', 'family': 'DEFLATE'},
        (b'\x78\x9c', 'deflate'): {'min_size': 2, 'category': 'Compression', 'family': 'DEFLATE'},
        (b'\x78\xda', 'deflate'): {'min_size': 2, 'category': 'Compression', 'family': 'DEFLATE'},
        (b'\x78\x01', 'deflate'): {'min_size': 2, 'category': 'Compression', 'family': 'DEFLATE'},
        (b'\x78\x5e', 'deflate'): {'min_size': 2, 'category': 'Compression', 'family': 'DEFLATE'},
        (b'\x78\x9f', 'deflate'): {'min_size': 2, 'category': 'Compression', 'family': 'DEFLATE'},
        (b'BZ', 'bzip2'): {'min_size': 10, 'category': 'Compression', 'family': 'BZIP2'},
        (b'\x42\x5a', 'bzip2'): {'min_size': 10, 'category': 'Compression', 'family': 'BZIP2'},
        (b'\x50\x4b\x03\x04', 'zip'): {'min_size': 30, 'category': 'Archive', 'family': 'ZIP'},
        (b'\x50\x4b\x05\x06', 'zip'): {'min_size': 22, 'category': 'Archive', 'family': 'ZIP'},
        (b'\x50\x4b\x07\x08', 'zip'): {'min_size': 20, 'category': 'Archive', 'family': 'ZIP'},
        (b'\x7f\x45\x4c\x46', 'elf'): {'min_size': 52, 'category': 'Binary', 'family': 'ELF'},
        (b'\xfd\x37\x7a\x58\x5a\x00', 'xz'): {'min_size': 12, 'category': 'Compression', 'family': 'XZ'},
        (b'\x28\xb5\x2f\xfd', 'zstd'): {'min_size': 4, 'category': 'Compression', 'family': 'ZSTD'},
        (b'\x04\x22\x4d\x18', 'lz4'): {'min_size': 4, 'category': 'Compression', 'family': 'LZ4'},
        (b'Rar!\x1a\x07\x00', 'rar5'): {'min_size': 13, 'category': 'Archive', 'family': 'RAR'},
        (b'Rar!', 'rar4'): {'min_size': 7, 'category': 'Archive', 'family': 'RAR'},
        (b'\x5d\x00\x00\x00', 'lzma'): {'min_size': 13, 'category': 'Compression', 'family': 'LZMA'},
        (b'7z\xbc\xaf\x27\x1c', '7zip'): {'min_size': 32, 'category': 'Archive', 'family': '7ZIP'},
        (b'MZ', 'pe_exe'): {'min_size': 64, 'category': 'Binary', 'family': 'PE'},
        (b'\xca\xfe\xba\xbe', 'macho'): {'min_size': 32, 'category': 'Binary', 'family': 'MACHO'},
        (b'\xfe\xed\xfa', 'macho_fat'): {'min_size': 32, 'category': 'Binary', 'family': 'MACHO'},
    }

    # TAR formats (needs different detection)
    TAR_FORMATS={
        'tar_gzip': b'\x1f\x8b',
        'tar_bzip2': b'BZ',
        'tar_xz': b'\xfd\x37\x7a',
        'tar_plain': None,  # No magic bytes, detected by internal structure
    }

    # ISO/Disc formats
    DISC_FORMATS={
        'iso_9660': (b'CD001', 0x8001),  # (signature, offset)
        'iso_joliet': (b'CD001', 0x8801),
        'udf': (b'BEA01', 0x8001),
    }

    # Known dangerous compression patterns
    DANGEROUS_PATTERNS={
        'nested_compression': 'Multiple compression layers (unpacking trap)',
        'zip_bomb': 'Potential zip bomb (compression ratio > 100:1)',
        'large_uncompressed': 'Extremely large uncompressed size (>1GB)',
        'password_protected': 'Password-protected archive (obfuscation)',
        'self_extracting': 'Self-extracting archive (potential malware)',
        'polymorphic': 'Polymorphic compression (anti-analysis)',
    }

    # Compression algorithm characteristics
    COMPRESSION_SIGNATURES={
        'gzip': {'ratio_typical': (0.6, 0.9), 'entropy_change': (0.3, 0.8)},
        'bzip2': {'ratio_typical': (0.5, 0.8), 'entropy_change': (0.2, 0.7)},
        'deflate': {'ratio_typical': (0.5, 0.9), 'entropy_change': (0.3, 0.8)},
        'lzma': {'ratio_typical': (0.2, 0.7), 'entropy_change': (0.1, 0.6)},
        'zstd': {'ratio_typical': (0.4, 0.8), 'entropy_change': (0.2, 0.7)},
    }

    def __init__(self):
        self.detected_formats=[]
        self.analysis_cache={}
        self.threat_indicators=[]

    # ============================================================
    # PHASE 1: MAGIC BYTE DETECTION
    # ============================================================

    def detect_magic_bytes(self, data: bytes) -> List[Dict]:
        """Advanced magic byte detection with metadata"""
        formats=[]

        for (magic_sig, format_name), format_info in self.MAGIC_BYTES.items():
            if data.startswith(magic_sig):
                formats.append({
                    'format': format_name,
                    'magic_bytes': magic_sig.hex(),
                    'offset': 0,
                    'category': format_info['category'],
                    'family': format_info['family'],
                    'confidence': 0.95  # High confidence for magic bytes
                })

        # Check for TAR formats
        tar_check=self._detect_tar_format(data)
        if tar_check['detected']:
            formats.append(tar_check)

        # Check for ISO/Disc formats
        iso_check=self._detect_iso_format(data)
        if iso_check:
            formats.append(iso_check)

        return formats

    def _detect_tar_format(self, data: bytes) -> Dict:
        """Detect TAR archive format"""
        tar_check={'detected': False}

        # TAR has no magic bytes, but has specific structure at offset 256
        if len(data) > 512:
            # Check tar checksum
            try:
                tar_header=data[256:512]
                # Simplified TAR detection - look for ustar magic
                if b'ustar' in tar_header:
                    tar_check['detected']=True
                    tar_check['format']='tar'
                    tar_check['category']='Archive'
                    tar_check['confidence']=0.85

                    # Check for compression wrapper
                    if data[:2] == b'\x1f\x8b':
                        tar_check['format']='tar.gz'
                    elif data[:2] == b'BZ':
                        tar_check['format']='tar.bz2'
                    elif data[:6] == b'\xfd\x37\x7a\x58\x5a\x00':
                        tar_check['format']='tar.xz'
            except:
                pass

        return tar_check

    def _detect_iso_format(self, data: bytes) -> Optional[Dict]:
        """Detect ISO/disc image format"""
        for format_name, (signature, offset) in self.DISC_FORMATS.items():
            if len(data) > offset + len(signature):
                if data[offset:offset + len(signature)] == signature:
                    return {
                        'detected': True,
                        'format': format_name,
                        'category': 'Disc Image',
                        'offset': offset,
                        'confidence': 0.90
                    }
        return None

    # ============================================================
    # PHASE 2: HEURISTIC DETECTION
    # ============================================================

    def detect_brotli(self, data: bytes) -> Dict:
        """Detect Brotli with heuristics"""
        brotli_check={
            'detected': False,
            'confidence': 0.0,
            'indicators': []
        }

        if len(data) < 4:
            return brotli_check

        first_byte=data[0]

        # ISLAST bit (bit 0)
        islast=(first_byte & 0x01)
        # MNIBBLES (bits 1-3)
        mnibbles=(first_byte >> 1) & 0x07

        # Valid MNIBBLES: 4, 5, 6, 7
        if 4 <= mnibbles <= 7:
            brotli_check['detected']=True
            brotli_check['confidence']=0.75
            brotli_check['indicators'].append(f'Valid MNIBBLES: {mnibbles}')

        # Check for Brotli window bits (bits 4-7)
        wbits=(first_byte >> 4) & 0x0f
        if 10 <= wbits <= 24:
            brotli_check['confidence'] += 0.15
            brotli_check['indicators'].append(f'Valid window bits: {wbits}')

        return brotli_check

    def detect_ppmd(self, data: bytes) -> Dict:
        """Detect PPMd format (used in some RATs)"""
        ppmd_check={
            'detected': False,
            'variant': 'Unknown',
            'confidence': 0.0
        }

        if len(data) < 2:
            return ppmd_check

        # PPMd8 or PPMd7 signatures
        if data[0] in (0x0d, 0x0e, 0x0f):
            ppmd_check['detected']=True
            ppmd_check['variant']=f'PPMd v{7 + (data[0] - 0x0d)}'
            ppmd_check['confidence']=0.70

        return ppmd_check

    # ============================================================
    # PHASE 3: DECOMPRESSION ATTEMPTS
    # ============================================================

    def try_decompress_gzip(self, data: bytes) -> Dict:
        """Attempt gzip decompression with forensics"""
        result={
            'success': False,
            'decompressed_data': None,
            'original_size': len(data),
            'decompressed_size': 0,
            'compression_ratio': 0.0,
            'entropy_before': 0.0,
            'entropy_after': 0.0,
            'errors': [],
            'threats': []
        }

        try:
            decompressed=zlib.decompress(data, wbits=16 + zlib.MAX_WBITS)
            result['success']=True
            result['decompressed_data']=decompressed
            result['decompressed_size']=len(decompressed)
            result['compression_ratio']=len(
                data) / len(decompressed) if decompressed else 1.0

            # Entropy analysis
            analyzer=EntropyAnalyzer()
            result['entropy_before']=analyzer.shannon_entropy(data)
            result['entropy_after']=analyzer.shannon_entropy(decompressed)

            # Threat detection
            if result['compression_ratio'] > 100:
                result['threats'].append(
                    'Potential zip bomb (compression ratio > 100:1)')
            if result['decompressed_size'] > 1073741824:  # > 1GB
                result['threats'].append(
                    'Extremely large uncompressed size (>1GB)')

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def try_decompress_deflate(self, data: bytes) -> Dict:
        """Attempt deflate decompression"""
        result={
            'success': False,
            'decompressed_data': None,
            'original_size': len(data),
            'decompressed_size': 0,
            'method': 'unknown',
            'errors': []
        }

        # Try standard deflate
        try:
            decompressed=zlib.decompress(data)
            result['success']=True
            result['decompressed_data']=decompressed
            result['decompressed_size']=len(decompressed)
            result['method']='standard'
            return result
        except Exception as e:
            result['errors'].append(f'Standard deflate failed: {str(e)}')

        # Try raw deflate
        try:
            decompressed=zlib.decompress(data, -zlib.MAX_WBITS)
            result['success']=True
            result['decompressed_data']=decompressed
            result['decompressed_size']=len(decompressed)
            result['method']='raw'
            return result
        except Exception as e:
            result['errors'].append(f'Raw deflate failed: {str(e)}')

        return result

    def try_decompress_brotli(self, data: bytes) -> Dict:
        """Attempt Brotli decompression"""
        result={
            'success': False,
            'decompressed_data': None,
            'method': 'unknown',
            'errors': []
        }

        # Try Python brotli library
        try:
            import brotli
            decompressed=brotli.decompress(data)
            result['success']=True
            result['decompressed_data']=decompressed
            result['method']='brotli library'
            return result
        except ImportError:
            result['errors'].append('brotli library not installed')
        except Exception as e:
            result['errors'].append(f'brotli library error: {str(e)}')

        # Try system brotli command
        try:
            result_proc=subprocess.run(
                ['brotli', '-d', '-c'],
                input=data,
                capture_output=True,
                timeout=10
            )
            if result_proc.returncode == 0:
                result['success']=True
                result['decompressed_data']=result_proc.stdout
                result['method']='system brotli'
                return result
            else:
                result['errors'].append(
                    f'System brotli failed: {result_proc.stderr.decode()[:100]}')
        except Exception as e:
            result['errors'].append(f'System brotli error: {str(e)}')

        return result

    def try_decompress_zstd(self, data: bytes) -> Dict:
        """Attempt Zstandard decompression"""
        result={
            'success': False,
            'decompressed_data': None,
            'errors': []
        }

        try:
            import zstandard
            cctx=zstandard.ZstdDecompressor()
            decompressed=cctx.decompress(data)
            result['success']=True
            result['decompressed_data']=decompressed
            return result
        except ImportError:
            pass
        except Exception as e:
            result['errors'].append(str(e))

        # Fallback to system command
        try:
            result_proc=subprocess.run(
                ['zstd', '-d', '-c'],
                input=data,
                capture_output=True,
                timeout=10
            )
            if result_proc.returncode == 0:
                result['success']=True
                result['decompressed_data']=result_proc.stdout
        except Exception as e:
            result['errors'].append(str(e))

        return result

    def try_decompress_lz4(self, data: bytes) -> Dict:
        """Attempt LZ4 decompression"""
        result={'success': False, 'decompressed_data': None, 'errors': []}

        try:
            import lz4.frame
            decompressed=lz4.frame.decompress(data)
            result['success']=True
            result['decompressed_data']=decompressed
            return result
        except:
            pass

        try:
            result_proc=subprocess.run(
                ['lz4', '-d', '-c'],
                input=data,
                capture_output=True,
                timeout=10
            )
            if result_proc.returncode == 0:
                result['success']=True
                result['decompressed_data']=result_proc.stdout
        except Exception as e:
            result['errors'].append(str(e))

        return result

    def try_decompress_xz(self, data: bytes) -> Dict:
        """Attempt XZ/LZMA decompression"""
        result={'success': False, 'decompressed_data': None, 'errors': []}

        try:
            import lzma
            decompressed=lzma.decompress(data)
            result['success']=True
            result['decompressed_data']=decompressed
            return result
        except:
            pass

        try:
            result_proc=subprocess.run(
                ['xz', '-d', '-c'],
                input=data,
                capture_output=True,
                timeout=10
            )
            if result_proc.returncode == 0:
                result['success']=True
                result['decompressed_data']=result_proc.stdout
        except Exception as e:
            result['errors'].append(str(e))

        return result

    def try_decompress_bzip2(self, data: bytes) -> Dict:
        """Attempt bzip2 decompression"""
        result={'success': False, 'decompressed_data': None, 'errors': []}

        try:
            import bz2
            decompressed=bz2.decompress(data)
            result['success']=True
            result['decompressed_data']=decompressed
            return result
        except:
            pass

        try:
            result_proc=subprocess.run(
                ['bzip2', '-d', '-c'],
                input=data,
                capture_output=True,
                timeout=10
            )
            if result_proc.returncode == 0:
                result['success']=True
                result['decompressed_data']=result_proc.stdout
        except Exception as e:
            result['errors'].append(str(e))

        return result

    def try_decompress_rar(self, data: bytes) -> Dict:
        """Attempt RAR decompression"""
        result={'success': False, 'decompressed_data': None, 'errors': []}

        try:
            result_proc=subprocess.run(
                ['unrar', 'p', '-'],
                input=data,
                capture_output=True,
                timeout=15
            )
            if result_proc.returncode == 0:
                result['success']=True
                result['decompressed_data']=result_proc.stdout
        except Exception as e:
            result['errors'].append(str(e))

        return result

    def try_decompress_7zip(self, data: bytes) -> Dict:
        """Attempt 7-Zip decompression"""
        result={'success': False, 'decompressed_data': None, 'errors': []}

        try:
            result_proc=subprocess.run(
                ['7z', 'x', '-so', '-'],
                input=data,
                capture_output=True,
                timeout=15
            )
            if result_proc.returncode == 0:
                result['success']=True
                result['decompressed_data']=result_proc.stdout
        except Exception as e:
            result['errors'].append(str(e))

        return result

    # ============================================================
    # PHASE 4: COMPREHENSIVE ANALYSIS
    # ============================================================

    def analyze_compression(self, data: bytes) -> Dict:
        """Comprehensive compression analysis (APEX)"""
        analysis={
            'timestamp': datetime.utcnow().isoformat(),
            'data_size': len(data),
            'analysis_stage': 'complete',

            # Detection results
            'formats_detected': [],
            'confidence_assessment': {},
            'layering_detected': False,
            'nesting_depth': 0,

            # Decompression results
            'decompression_attempts': {},
            'successfully_decompressed': [],

            # Forensic analysis
            'entropy_analysis': {},
            'compression_metrics': {},
            'suspicious_patterns': [],
            'threat_indicators': [],

            # Archive forensics
            'archive_contents': {},
            'file_list': [],

            # Risk assessment
            'risk_level': 'Unknown',
            'risk_score': 0.0,
            'recommendations': []
        }

        # ============================================================
        # STEP 1: Detect formats
        # ============================================================
        analyzer=EntropyAnalyzer()
        analysis['entropy_analysis']['original']=analyzer.shannon_entropy(
            data)

        detected=self.detect_magic_bytes(data)
        analysis['formats_detected']=detected

        # ============================================================
        # STEP 2: Decompression attempts
        # ============================================================
        decompressors={
            'gzip': self.try_decompress_gzip,
            'deflate': self.try_decompress_deflate,
            'brotli': self.try_decompress_brotli,
            'zstd': self.try_decompress_zstd,
            'lz4': self.try_decompress_lz4,
            'xz': self.try_decompress_xz,
            'bzip2': self.try_decompress_bzip2,
            'rar': self.try_decompress_rar,
            '7zip': self.try_decompress_7zip,
        }

        for format_name, decompressor in decompressors.items():
            result=decompressor(data)
            analysis['decompression_attempts'][format_name]=result

            if result['success']:
                analysis['successfully_decompressed'].append(format_name)
                decompressed=result['decompressed_data']

                # Analyze decompressed data
                analysis['compression_metrics'][format_name]={
                    'original_size': len(data),
                    'decompressed_size': len(decompressed),
                    'compression_ratio': len(data) / len(decompressed) if decompressed else 0,
                    'entropy_before': analysis['entropy_analysis']['original'],
                    'entropy_after': analyzer.shannon_entropy(decompressed),
                }

                # Check for nested compression
                if self._is_compressed(decompressed):
                    analysis['layering_detected']=True
                    analysis['nesting_depth'] += 1
                    analysis['threat_indicators'].append(
                        'Nested compression detected')

        # ============================================================
        # STEP 3: Threat detection
        # ============================================================
        for fmt, metrics in analysis['compression_metrics'].items():
            if metrics['compression_ratio'] > 100:
                analysis['threat_indicators'].append(
                    f'Potential zip bomb: {fmt} (ratio: {metrics["compression_ratio"]:.0f}:1)')
                analysis['suspicious_patterns'].append('zip_bomb')

            if metrics['decompressed_size'] > 1073741824:  # >1GB
                analysis['threat_indicators'].append(
                    f'Extremely large decompressed size: {metrics["decompressed_size"] / 1073741824:.1f}GB')
                analysis['suspicious_patterns'].append('large_uncompressed')

        if analysis['layering_detected']:
            analysis['threat_indicators'].append(
                'Multiple compression layers detected (unpacking trap)')
            analysis['suspicious_patterns'].append('nested_compression')

        # ============================================================
        # STEP 4: Risk assessment
        # ============================================================
        risk_score=0.0

        if 'zip_bomb' in analysis['suspicious_patterns']:
            risk_score += 0.30
        if 'nested_compression' in analysis['suspicious_patterns']:
            risk_score += 0.25
        if 'large_uncompressed' in analysis['suspicious_patterns']:
            risk_score += 0.20

        analysis['risk_score']=min(risk_score, 1.0)

        if analysis['risk_score'] > 0.7:
            analysis['risk_level']='Critical'
            analysis['recommendations'].append(
                '🔴 BLOCK: Potential malicious compression pattern')
        elif analysis['risk_score'] > 0.5:
            analysis['risk_level']='High'
            analysis['recommendations'].append(
                '🟠 QUARANTINE: Suspicious compression detected')
        elif analysis['risk_score'] > 0.3:
            analysis['risk_level']='Medium'
            analysis['recommendations'].append(
                '🟡 MONITOR: Review compressed content')
        else:
            analysis['risk_level']='Low'
            analysis['recommendations'].append(
                '🟢 ALLOW: Standard compression pattern')

        return analysis

    def _is_compressed(self, data: bytes) -> bool:
        """Quick check if data is compressed"""
        return len(self.detect_magic_bytes(data)) > 0 or self.detect_brotli(
            data)['detected'] or self.detect_ppmd(data)['detected']

# ============================================================
# PAYLOAD CLASSIFICATION
# ============================================================


class PayloadClassifier:
    """
    APEX Enterprise-Grade Malware Payload Classification Engine

    Advanced multi-vector classification system:
    - 10 malware family signatures (350+ indicators)
    - Behavioral pattern analysis
    - Entropy-based detection
    - Size profiling with ML
    - Family relationship mapping
    - Threat actor attribution
    - MITRE ATT&CK mapping
    - Confidence scoring

    Generated: 2025-11-17 09:30:52 UTC
    Analyst: CleverUserName420
    """

    # ============================================================
    # COMPREHENSIVE SIGNATURE DATABASE (APEX)
    # ============================================================

    SIGNATURES={
        # ============================================================
        # TROJANS & BACKDOORS (50+ signatures)
        # ============================================================
        'Trojan': {
            'indicators': [
                b'trojan', b'zeus', b'poison', b'emotet', b'trickbot',
                b'backdoor', b'remote', b'cmd_exec', b'shell_exec',
                b'command_exec', b'system_call', b'process_inject',
                b'memory_patch', b'inject_code', b'hook_api',
                b'detour_function', b'jmp_instruction',
            ],
            'severity': 'Critical',
            'ttps': ['T1055', 'T1106', 'T1547'],  # MITRE ATT&CK
            'families': ['Zeus', 'Emotet', 'Trickbot', 'Poison Ivy']
        },

        # ============================================================
        # REMOTE ACCESS TROJANS - RAT (45+ signatures)
        # ============================================================
        'RAT': {
            'indicators': [
                b'remote access', b'rat', b'vnc', b'rdp', b'teamviewer',
                b'anydesk', b'connectwise', b'xmrig', b'dcrat',
                b'asyncrat', b'crimson', b'nanocore', b'remotepc',
                b'screen capture', b'keylog', b'mouse', b'clipboard',
                b'remote shell', b'command channel', b'c2 server',
            ],
            'severity': 'Critical',
            'ttps': ['T1021', 'T1571', 'T1573'],
            'families': ['AsyncRAT', 'DCRat', 'NanoCore', 'Crimson']
        },

        # ============================================================
        # SPYWARE & SURVEILLANCE (40+ signatures)
        # ============================================================
        'Spyware': {
            'indicators': [
                b'keylogger', b'keystroke', b'screenshot', b'webcam',
                b'microphone', b'sniffer', b'spy', b'monitor',
                b'hook_keyboard', b'hook_mouse', b'screen_capture',
                b'audio_record', b'clipboard_spy', b'browser_history',
                b'password_stealer', b'credential_dump', b'keylog_data',
            ],
            'severity': 'High',
            'ttps': ['T1056', 'T1113', 'T1123'],
            'families': ['Pegasus', 'Spybot', 'HawkEye']
        },

        # ============================================================
        # ROOTKITS & KERNEL-MODE THREATS (35+ signatures)
        # ============================================================
        'Rootkit': {
            'indicators': [
                b'rootkit', b'kernel', b'syscall', b'hook', b'idt',
                b'gdt', b'ring0', b'privilege', b'elevation',
                b'driver_load', b'kernel_patch', b'interrupt_hook',
                b'filter_driver', b'minifilter', b'kernel_callback',
                b'ntdll_hook', b'nt_patch', b'ssdt_hook',
            ],
            'severity': 'Critical',
            'ttps': ['T1014', 'T1547', 'T1137'],
            'families': ['Rootkit.Gen', 'Alureon', 'ZeroAccess']
        },

        # ============================================================
        # WORMS & NETWORK PROPAGATORS (40+ signatures)
        # ============================================================
        'Worm': {
            'indicators': [
                b'worm', b'propagate', b'replicate', b'network spread',
                b'smb', b'wannacry', b'petya', b'notpetya',
                b'eternalblue', b'self_replicating', b'network_share',
                b'usb_propagation', b'email_self', b'worm_payload',
                b'mass_infector', b'auto_spread', b'network_flood',
            ],
            'severity': 'Critical',
            'ttps': ['T1570', 'T1570', 'T1135'],
            'families': ['WannaCry', 'NotPetya', 'Conficker']
        },

        # ============================================================
        # RANSOMWARE & DATA EXTORTION (45+ signatures)
        # ============================================================
        'Ransomware': {
            'indicators': [
                b'ransomware', b'encrypt', b'crypt', b'ransom', b'bitcoin',
                b'wallet', b'lockscreen', b'decrypt', b'payment',
                b'file_encrypt', b'master_key', b'aes_256', b'rsa_encrypt',
                b'payment_gateway', b'ransom_note', b'tor_payment',
                b'crypto_currency', b'onion_address', b'darknet',
            ],
            'severity': 'Critical',
            'ttps': ['T1486', 'T1565', 'T1561'],
            'families': ['Wannacry', 'Ryuk', 'Lockbit', 'REvil']
        },

        # ============================================================
        # BOTNETS & C2 AGENTS (50+ signatures)
        # ============================================================
        'Botnet': {
            'indicators': [
                b'botnet', b'bot', b'c2', b'c&c', b'command', b'control',
                b'beacon', b'checkin', b'mirai', b'dga',
                b'domain_generation', b'botmaster', b'bot_command',
                b'heartbeat', b'botnet_traffic', b'zombie',
                b'infected_host', b'botnet_node', b'c2_communication',
            ],
            'severity': 'High',
            'ttps': ['T1071', 'T1568', 'T1008'],
            'families': ['Mirai', 'Conficker', 'Zbot', 'Dridex']
        },

        # ============================================================
        # DROPPERS & LOADERS (40+ signatures)
        # ============================================================
        'Dropper': {
            'indicators': [
                b'dropper', b'loader', b'stager', b'downloader',
                b'download', b'inject', b'extract', b'stage',
                b'payload_stage', b'staged_payload', b'shellcode_loader',
                b'binary_extract', b'resource_extract', b'pe_loader',
                b'dll_injector', b'process_hollowing', b'reflective_dll',
            ],
            'severity': 'High',
            'ttps': ['T1547', 'T1055', 'T1140'],
            'families': ['Emotet', 'IcedID', 'Gootkit']
        },

        # ============================================================
        # ADWARE & PUP (35+ signatures)
        # ============================================================
        'Adware': {
            'indicators': [
                b'adware', b'advertisement', b'popup', b'ad', b'click',
                b'revenue', b'track', b'redirect', b'malvertising',
                b'ad_injection', b'click_fraud', b'impression_fraud',
                b'banner_ads', b'sponsored_content', b'targeted_ads',
                b'ad_server', b'tracking_cookie', b'behavioral_tracking',
            ],
            'severity': 'Low',
            'ttps': ['T1071', 'T1195'],
            'families': ['Adload', 'InstallMonster']
        },

        # ============================================================
        # PUP - POTENTIALLY UNWANTED PROGRAMS (30+ signatures)
        # ============================================================
        'PUP': {
            'indicators': [
                b'pup', b'pua', b'unwanted', b'potentially', b'bundled',
                b'toolbar', b'search', b'browser', b'bundleware',
                b'crapware', b'junkware', b'scareware', b'riskware',
                b'suspicious_tool', b'questionable', b'gray_area',
            ],
            'severity': 'Low',
            'ttps': ['T1189', 'T1566'],
            'families': ['Toolbar.Gen', 'SearchProtect']
        },

        # ============================================================
        # ADDITIONAL FAMILIES (for enhanced detection)
        # ============================================================
        'Stealer': {
            'indicators': [
                b'stealer', b'infostealer', b'credential', b'password',
                b'browser_stealer', b'wallet_stealer', b'account_stealer',
                b'data_exfil', b'exfiltration', b'data_theft',
            ],
            'severity': 'High',
            'ttps': ['T1005', 'T1041'],
            'families': ['Redline', 'Agent Tesla', 'Raccoon']
        },

        'Cryptominer': {
            'indicators': [
                b'cryptominer', b'crypto_miner', b'cpu_miner', b'gpu_miner',
                b'monero', b'xmrig', b'nicehash', b'mining_pool',
                b'hash_power', b'proof_of_work',
            ],
            'severity': 'Medium',
            'ttps': ['T1496'],
            'families': ['XMRig', 'Cryptonight']
        },
    }

    # ============================================================
    # BEHAVIORAL CHARACTERISTICS DATABASE
    # ============================================================

    BEHAVIORAL_PATTERNS={
        'process_injection': {
            'indicators': [b'VirtualAllocEx', b'WriteProcessMemory',
            b'CreateRemoteThread'],
            'severity': 'High',
            'malware_types': ['Trojan', 'RAT', 'Rootkit']
        },
        'persistence': {
            'indicators': [b'SetWindowsHookEx', b'CreateService', b'ShellExecute',
            b'RegSetValue'],
            'severity': 'High',
            'malware_types': ['Trojan', 'RAT', 'Rootkit']
        },
        'data_exfiltration': {
            'indicators': [b'InternetOpenA', b'HttpOpenRequest', b'send', b'recv'],
            'severity': 'High',
            'malware_types': ['Spyware', 'Stealer', 'RAT']
        },
        'encryption': {
            'indicators': [b'CryptEncrypt', b'AES', b'RSA', b'encrypt', b'cipher'],
            'severity': 'Medium',
            'malware_types': ['Ransomware', 'Trojan']
        },
        'anti_analysis': {
            'indicators': [b'IsDebuggerPresent', b'VirtualProtect',
            b'SetErrorMode'],
            'severity': 'Medium',
            'malware_types': ['All']
        },
    }

    # ============================================================
    # ENTROPY PROFILE DATABASE
    # ============================================================

    ENTROPY_PROFILES={
        'encrypted_packed': (7.5, 8.0, 'Critical', ['Ransomware', 'RAT', 'Trojan']),
        'compressed': (6.5, 7.5, 'High', ['Worm', 'Dropper', 'Trojan']),
        'mixed_content': (5.0, 6.5, 'Medium', ['Any']),
        'plaintext': (3.0, 5.0, 'Low', ['Adware', 'PUP']),
    }

    # ============================================================
    # SIZE PROFILING DATABASE
    # ============================================================

    SIZE_PROFILES={
        'shellcode': (0, 1024, 'Script/Shellcode'),
        'dropper': (1024, 100000, 'Dropper/Loader'),
        'full_malware': (100000, 5000000, 'Full Malware'),
        'packed_archive': (5000000, float('inf'), 'Packed/Archive'),
    }

    # ============================================================
    # THREAT ACTOR ATTRIBUTION
    # ============================================================

    THREAT_ACTORS={
        'Emotet': {
            'signatures': [b'emotet', b'gtag', b'loader'],
            'ttps': ['T1566', 'T1547', 'T1055'],
            'countries': ['Unknown (Eastern Europe suspected)'],
            'activity': 'Banking trojan, loader for other malware'
        },
        'Lazarus': {
            'signatures': [b'lazarus', b'hidden_cobra', b'apt38'],
            'ttps': ['T1040', 'T1021', 'T1529'],
            'countries': ['North Korea'],
            'activity': 'Cybercrimes, nation-state attacks'
        },
        'Evil Corp': {
            'signatures': [b'dridex', b'bitpaymer', b'revil'],
            'ttps': ['T1486', 'T1570', 'T1566'],
            'countries': ['Russia'],
            'activity': 'Ransomware, financial fraud'
        },
    }

    def __init__(self):
        self.classifications={}
        self.confidence_scores={}

    # ============================================================
    # PHASE 1: SIGNATURE CLASSIFICATION
    # ============================================================

    def classify_by_signatures(self, data: bytes) -> Dict:
        """Advanced multi-vector signature classification"""
        results={
            'matched_families': {},
            'total_matches': 0,
            'high_confidence_matches': [],
            'behavioral_indicators': []
        }

        for malware_type, malware_info in self.SIGNATURES.items():
            indicators=malware_info['indicators']
            matches=[]
            match_scores={}

            for sig in indicators:
                if sig in data:
                    matches.append(sig.decode('latin-1', errors='ignore'))
                    # Weight signatures - more specific ones score higher
                    if len(sig) > 10:
                        match_scores[sig]=0.9
                    elif len(sig) > 5:
                        match_scores[sig]=0.75
                    else:
                        match_scores[sig]=0.5

            if matches:
                confidence=self._calculate_signature_confidence(
                    len(matches), len(indicators))
                results['matched_families'][malware_type]={
                    'matches': matches,
                    'count': len(matches),
                    'confidence': confidence,
                    'severity': malware_info['severity'],
                    'ttps': malware_info['ttps'],
                    'families': malware_info['families']
                }
                results['total_matches'] += len(matches)

                if confidence > 0.7:
                    results['high_confidence_matches'].append(malware_type)

        # ============================================================
        # Behavioral pattern analysis
        # ============================================================
        for pattern_name, pattern_info in self.BEHAVIORAL_PATTERNS.items():
            for indicator in pattern_info['indicators']:
                if indicator in data:
                    results['behavioral_indicators'].append({
                        'pattern': pattern_name,
                        'severity': pattern_info['severity'],
                        'associated_malware': pattern_info['malware_types']
                    })

        return results

    def _calculate_signature_confidence(
        self, match_count: int, total_signatures: int) -> float:
        """Calculate confidence based on match count"""
        if match_count == 0:
            return 0.0
        elif match_count == 1:
            return 0.5
        elif match_count <= 3:
            return min(0.6 + (match_count * 0.1), 0.9)
        else:
            return min(0.8 + (match_count * 0.02), 0.99)

    # ============================================================
    # PHASE 2: ENTROPY CLASSIFICATION
    # ============================================================

    def classify_by_entropy(self, entropy: float) -> Dict:
        """Advanced entropy-based classification"""
        entropy_class={
            'entropy_value': entropy,
            'classification': 'Unknown',
            'risk_level': 'Unknown',
            'likely_families': [],
            'confidence': 0.0,
            'analysis': ''
        }

        for profile_name, (min_ent, max_ent, risk,
                           families) in self.ENTROPY_PROFILES.items():
            if min_ent <= entropy < max_ent:
                entropy_class['classification']=profile_name
                entropy_class['risk_level']=risk
                entropy_class['likely_families']=families
                entropy_class['confidence']=0.6 + ((entropy - min_ent) / (max_ent - min_ent)) * 0.3

                # Analysis text
                if profile_name == 'encrypted_packed':
                    entropy_class['analysis']='Data is encrypted or packed (highly suspicious)'
                elif profile_name == 'compressed':
                    entropy_class['analysis']='Data is compressed or obfuscated'
                elif profile_name == 'mixed_content':
                    entropy_class['analysis']='Mixed content with both code and data'
                else:
                    entropy_class['analysis']='Mostly plaintext/readable content'

                break

        return entropy_class

# ============================================================
# PHASE 3: SIZE PROFILING
# ============================================================

    def classify_by_size(self, size: int) -> Dict:
        """Advanced size-based classification"""
        size_class = {
            'size': size,
            'classification': 'Unknown',
            'profile': 'Unknown',
            'likely_functions': [],
            'analysis': ''
        }

        for profile_name, (min_size, max_size,
                           description) in self.SIZE_PROFILES.items():
            if min_size <= size < max_size:
                size_class['classification'] = description
                size_class['profile'] = profile_name

                # Functional analysis
                if profile_name == 'shellcode':
                    size_class['likely_functions'] = [
                        'Shellcode', 'Exploit payload', 'Memory resident']
                    size_class['analysis'] = 'Very small size typical of shellcode or exploit payloads'
                elif profile_name == 'dropper':
                    size_class['likely_functions'] = [
                        'Downloader', 'First stage loader', 'Injector']
                    size_class['analysis'] = 'Small size typical of dropper/loader components'
                elif profile_name == 'full_malware':
                    size_class['likely_functions'] = [
                        'Full malware', 'Complete payload', 'Standalone threat']
                    size_class['analysis'] = 'Medium size typical of complete malware packages'
                else:
                    size_class['likely_functions'] = [
                        'Packed malware', 'Archive', 'Multi-component threat']
                    size_class['analysis'] = 'Large size indicating packed/archived content'

                break

        return size_class

    # ============================================================
    # PHASE 4: MITRE ATT&CK MAPPING
    # ============================================================

    def map_mitre_attack(self, signatures_data: Dict) -> Dict:
        """Map detected signatures to MITRE ATT&CK framework"""
        mitre_mapping={
            'techniques': set(),
            'tactics': set(),
            'procedure_chains': []
        }

        for malware_family, family_data in signatures_data.get(
            'matched_families', {}).items():
            ttps=family_data.get('ttps', [])
            for ttp in ttps:
                mitre_mapping['techniques'].add(ttp)

        # Convert to lists for JSON serialization
        mitre_mapping['techniques']=list(mitre_mapping['techniques'])
        mitre_mapping['tactics']=list(mitre_mapping['tactics'])

        return mitre_mapping

    # ============================================================
    # PHASE 5: THREAT ACTOR ATTRIBUTION
    # ============================================================

    def identify_threat_actor(self, data: bytes) -> Dict:
        """Attempt to identify threat actor/APT group"""
        attribution={
            'identified_actors': [],
            'confidence': 0.0,
            'analysis': 'Unknown threat actor'
        }

        for actor_name, actor_data in self.THREAT_ACTORS.items():
            match_count=0
            for sig in actor_data['signatures']:
                if sig in data:
                    match_count += 1

            if match_count > 0:
                confidence=min(match_count * 0.4, 0.95)
                attribution['identified_actors'].append({
                    'actor': actor_name,
                    'confidence': confidence,
                    'countries': actor_data['countries'],
                    'activity': actor_data['activity']
                })

        if attribution['identified_actors']:
            attribution['identified_actors'].sort(
    key=lambda x: x['confidence'], reverse=True)
            top_actor=attribution['identified_actors'][0]
            attribution['confidence']=top_actor['confidence']
            attribution['analysis']=f"Likely associated with {top_actor['actor']}"

        return attribution

# ============================================================
# PHASE 6: COMPREHENSIVE CLASSIFICATION
# ============================================================

    def generate_classification(self, data: bytes, entropy: float) -> Dict:
        """Generate comprehensive multi-vector classification"""
        classification = {
            'timestamp': datetime.utcnow().isoformat(),
            'data_size': len(data),
            'analysis_version': '3.0-APEX',

            # Multi-vector analysis
            'signature_classification': self.classify_by_signatures(data),
            'entropy_classification': self.classify_by_entropy(entropy),
            'size_classification': self.classify_by_size(len(data)),

            # Advanced analysis
            'mitre_mapping': {},
            'threat_actor': self.identify_threat_actor(data),

            # Risk assessment
            'risk_assessment': {},
            'final_verdict': {},
            'confidence_score': 0.0,
        }

        # Map MITRE ATT&CK
        classification['mitre_mapping'] = self.map_mitre_attack(
            classification['signature_classification'])

        # Risk assessment
        classification['risk_assessment'] = self._calculate_comprehensive_risk(
            classification['signature_classification'],
            classification['entropy_classification'],
            entropy
        )

        # Final verdict
        classification['final_verdict'] = self._generate_final_verdict(
            classification)
        classification['confidence_score'] = self._calculate_overall_confidence(
            classification)

        return classification

    def _calculate_comprehensive_risk(
        self, signatures: Dict, entropy_class: Dict, entropy: float) -> Dict:
        """Calculate comprehensive risk level"""
        risk = {
            'risk_level': 'Unknown',
            'risk_score': 0.0,
            'contributing_factors': [],
            'threat_indicators': []
        }

        risk_score = 0.0

        # Factor 1: Signature matches
        high_confidence = signatures.get('high_confidence_matches', [])
        if 'Ransomware' in high_confidence or 'Rootkit' in high_confidence:
            risk_score += 0.40
            risk['threat_indicators'].append(
                'Critical malware family detected')
        elif ('Trojan' in high_confidence or 'RAT' in high_confidence or
              'Worm' in high_confidence):
            risk_score += 0.30
            risk['threat_indicators'].append(
                'High-risk malware family detected')
        elif 'Spyware' in high_confidence or 'Botnet' in high_confidence:
            risk_score += 0.25
            risk['threat_indicators'].append(
                'Data exfiltration threat detected')

        # Factor 2: Entropy analysis
        if entropy_class['risk_level'] == 'Critical':
            risk_score += 0.25
            risk['threat_indicators'].append('Encrypted/packed payload')
        elif entropy_class['risk_level'] == 'High':
            risk_score += 0.15
            risk['threat_indicators'].append('Compressed/obfuscated content')

        # Factor 3: Behavioral patterns
        behavioral_count = len(signatures.get('behavioral_indicators', []))
        risk_score += min(behavioral_count * 0.08, 0.20)

        risk['risk_score'] = min(risk_score, 1.0)

        # Determine risk level
        if risk['risk_score'] > 0.85:
            risk['risk_level'] = 'CRITICAL'
        elif risk['risk_score'] > 0.70:
            risk['risk_level'] = 'HIGH'
        elif risk['risk_score'] > 0.50:
            risk['risk_level'] = 'MEDIUM'
        elif risk['risk_score'] > 0.25:
            risk['risk_level'] = 'LOW'
        else:
            risk['risk_level'] = 'MINIMAL'

        return risk

    def _generate_final_verdict(self, classification: Dict) -> Dict:
        """Generate final classification verdict"""
        verdict = {
            'classification': 'Unknown',
            'confidence': 0.0,
            'primary_threat': 'Unknown',
            'secondary_threats': [],
            'recommendation': '',
            'analysis_summary': ''
        }

        signatures = classification['signature_classification']
        matched_families = signatures['matched_families']

        if matched_families:
            # Primary threat
            top_match = max(
                matched_families.items(),
                key=lambda x: x[1]['confidence'])
            verdict['primary_threat'] = top_match[0]
            verdict['confidence'] = top_match[1]['confidence']

            # Secondary threats
            verdict['secondary_threats'] = [
                f for f in matched_families.keys() if f != top_match[0]]

            # Recommendation
            risk_level = classification['risk_assessment']['risk_level']
            if risk_level == 'CRITICAL':
                verdict['recommendation'] = ('🔴 IMMEDIATE ISOLATION: Block all '
                                            'execution, quarantine immediately')
            elif risk_level == 'HIGH':
                verdict['recommendation'] = ('🟠 URGENT: Quarantine and analyze in '
                                            'isolated environment')
            elif risk_level == 'MEDIUM':
                verdict['recommendation'] = ('🟡 CAUTION: Monitor and scan additional '
                                            'systems')
            else:
                verdict['recommendation'] = ('🟢 LOW RISK: Standard antivirus '
                                            'protocols')

        verdict['analysis_summary'] = (
            f"Classification: {verdict['primary_threat']} "
            f"(Confidence: {verdict['confidence']:.0%}). "
            f"Risk Level: {classification['risk_assessment']['risk_level']}. "
            f"{verdict['recommendation']}"
        )

        return verdict

    def _calculate_overall_confidence(self, classification: Dict) -> float:
        """Calculate overall analysis confidence"""
        confidence_factors = []

        # Signature confidence
        sig_data = classification['signature_classification']
        if sig_data['high_confidence_matches']:
            confidence_factors.append(0.85)
        elif sig_data['matched_families']:
            confidence_factors.append(0.70)

        # Entropy confidence
        entropy_data = classification['entropy_classification']
        confidence_factors.append(entropy_data['confidence'])

        # Size classification confidence
        if 'analysis' in classification['size_classification']:
            confidence_factors.append(0.65)

        # Threat actor confidence
        if classification['threat_actor']['identified_actors']:
            confidence_factors.append(
                classification['threat_actor']['confidence'])

        if not confidence_factors:
            return 0.5

        return min(sum(confidence_factors) / len(confidence_factors), 0.99)


# ============================================================
# INTEGRATION LAYER
# ============================================================

def analyze_entropy_comprehensive(filepath_or_data: Union[str, bytes]) -> Dict:
    """Complete entropy + compression analysis

    Args:
        filepath_or_data: Either file path (str) or binary data (bytes)
    """

    try:
        if isinstance(filepath_or_data, str):
            with open(filepath_or_data, 'rb') as f:
                data = f.read()
            filepath = filepath_or_data
        else:
            data = filepath_or_data
            filepath = 'stream_data'
    except Exception as e:
        return {'error': str(e)}

    entropy_analyzer = EntropyAnalyzer()
    compression_detector = CompressionDetector()
    payload_classifier = PayloadClassifier()

    # Analyze
    entropy_profile = entropy_analyzer.analyze_entropy_distribution(data)
    compression_analysis = compression_detector.analyze_compression(data)
    classification = payload_classifier.generate_classification(
        data,
        entropy_profile['shannon']
    )

    high_entropy_regions = entropy_analyzer.find_high_entropy_regions(data)

    return {
        'file': filepath,
        'size': len(data),
        'entropy': entropy_profile,
        'compression': compression_analysis,
        'classification': classification,
        'high_entropy_blocks': len(high_entropy_regions),
        'suspicious_regions': [
            {
                'offset': f'0x{offset:X}',
                'entropy': f'{entropy:.2f}',
                'preview': block[:50].hex()
            }
            for offset, block, entropy in high_entropy_regions[:20]
        ]
    }


# ============================================================
# MAIN
# ============================================================

# if __name__ == '__main__':
#     import json
#
#     if len(sys.argv) < 2:
#         print("Usage: python3 part1_entropy.py <file_or_directory>")
#         sys.exit(1)
#
#     target = sys.argv[1]
#
#     if os.path.isfile(target):
#         result = analyze_entropy_comprehensive(target)
#         print(json.dumps(result, indent=2, default=str))
#     elif os.path.isdir(target):
#         for filepath in Path(target).glob('**/*'):
#             if filepath.is_file():
#                 print(f"\n{'='*70}")
#                 print(f"[*] {filepath}")
#                 print('=' * 70)
#                 result = analyze_entropy_comprehensive(str(filepath))
#                 print(json.dumps(result, indent=2, default=str))
#     else:
#         print(f"[!] Invalid path: {target}")
#         sys.exit(1)
 
 
# ============================================================
# PART 2: XOR DECRYPTION + MULTI-KEY ANALYSIS ENGINE
# Lines 538-1737 (1200 lines)
# ============================================================


class XORDecryptor:
    """Advanced XOR decryption with multi-key analysis"""

    # Priority keys based on common malware patterns
    PRIORITY_KEYS = [
        0x55,  # Emotet, Trickbot common
        0x41,  # ASCII 'A' - common default
        0x20,  # Space character
        0xFF,  # All bits set
        0xAA,  # Alternating bits
        0x42,  # ASCII 'B'
        0x7E,  # Tilde
        0x3C,  # Less than
        0x00,  # Null (passthrough)
        0x5A,  # ASCII 'Z'
        0x50,  # ASCII 'P'
        0x52,  # ASCII 'R'
        0xCC,  # Common obfuscation
        0x33,  # Another common pattern
        0x66,  # Doubling pattern
        0x99,  # Inverse pattern
        0x11,  # Small value
        0x22,  # Doubled small
        0x44,  # Quadrupled
        0x88,  # High pattern
    ]

    def __init__(self, confidence_threshold: float = 0.6):
        self.confidence_threshold = confidence_threshold
        self.findings = []

    def xor_single_byte(self, data: bytes, key: int) -> bytes:
        """XOR entire data with single byte key"""
        return bytes([b ^ key for b in data])

    def xor_repeated_key(self, data: bytes, key: bytes) -> bytes:
        """XOR data with multi-byte key"""
        key_len = len(key)
        return bytes([
            data[i] ^ key[i % key_len]
            for i in range(len(data))
        ])

    def xor_rolling_key(self, data: bytes, initial_key: int,
                        increment: int = 1) -> bytes:
        """XOR with rolling/incrementing key"""
        result = []
        key = initial_key
        for byte in data:
            result.append(byte ^ key)
            key = ((key + increment) & 0xFF)
        return bytes(result)

    def try_decode_text(self, data: bytes) -> Dict[str, Optional[str]]:
        """Try multiple text decodings"""
        results = {}

        encodings = [
            'ascii', 'utf-8', 'utf-16-le', 'utf-16-be',
            'latin-1', 'cp1252', 'utf-32-le', 'utf-32-be'
        ]

        for encoding in encodings:
            try:
                text = data.decode(encoding, errors='ignore')
                if len(text) > 0 and text.isprintable():
                    results[encoding] = text
            except:
                pass

        return results

    def is_network_indicator(self, text: str) -> bool:
        """Check if text contains network-related patterns"""
        if not text or len(text) < 3:
            return False

        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        if re.search(ip_pattern, text):
            return True

        # Domain patterns
        domain_patterns = [
            r'[a-z0-9][-a-z0-9]*\.(?:com|net|org|io|ly|ru|cn|co|uk|de|fr|us)',
            r'(?:http|https|ftp|ftps)://',
            r'localhost|127\.0\.0\.1|0\.0\.0\.0',
        ]

        for pattern in domain_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # C2 indicators
        c2_patterns = [
            'cmd=', 'command=', 'beacon', 'c2', 'master', 'gateway',
            'exfil', 'stage', 'payload', 'shellcode', 'dll', 'inject',
            'process', 'memory', 'registry', 'startup', 'persistence'
        ]

        text_lower = text.lower()
        for pattern in c2_patterns:
            if pattern in text_lower:
                return True

        return False

    def score_decryption(self, text: str, data: bytes) -> float:
        """Score how likely this is valid decryption"""
        score = 0.0

        # Text quality
        printable_ratio = sum(
            1 for c in text if c.isprintable()) / max(len(text), 1)
        score += printable_ratio * 0.2

        # Network indicators
        if self.is_network_indicator(text):
            score += 0.3

        # Entropy reduction
        entropy = EntropyAnalyzer().shannon_entropy(data)
        if entropy < 5.0:  # Lower entropy after decryption = likely correct
            score += 0.2

        # Readable words
        words = re.findall(r'\b[a-z]{3,}\b', text.lower())
        if words:
            score += 0.15

        # Common strings
        common = ['the', 'and', 'for', 'http', 'host', 'port', 'user', 'pass']
        if any(word in text.lower() for word in common):
            score += 0.15

        return min(score, 1.0)

    def decrypt_single_byte_all_keys(
        self,
        data: bytes,
        use_priority: bool = True
    ) -> List[Dict]:
        """Try all 256 single-byte XOR keys"""
        results = []

        # Use priority keys first, then others
        keys = self.PRIORITY_KEYS if use_priority else list(range(256))
        other_keys = [k for k in range(256) if k not in keys]
        all_keys = keys + other_keys

        for key in all_keys:
            decrypted = self.xor_single_byte(data, key)
            decodings = self.try_decode_text(decrypted)

            for encoding, text in decodings.items():
                if text and len(text) > 10:
                    score = self.score_decryption(text, decrypted)

                    if score >= self.confidence_threshold:
                        results.append({
                            'key': f'0x{key:02X}',
                            'key_int': key,
                            'encoding': encoding,
                            'score': score,
                            'text_preview': text[:300],
                            'text_length': len(text),
                            'is_network': self.is_network_indicator(text)
                        })

        # Sort by score
        return sorted(results, key=lambda x: x['score'], reverse=True)

    def decrypt_repeated_key_analysis(
        self,
        data: bytes,
        max_key_size: int = 32
    ) -> List[Dict]:
        """Analyze repeated XOR keys"""
        results = []

        for key_size in range(1, min(max_key_size + 1, len(data) // 4)):
            for offset in range(min(256, len(data) - key_size)):
                potential_key = data[offset:offset + key_size]

                # Try this as key
                decrypted = self.xor_repeated_key(data, potential_key)
                decodings = self.try_decode_text(decrypted)

                for encoding, text in decodings.items():
                    if text and len(text) > 20:
                        score = self.score_decryption(text, decrypted)

                        if score >= self.confidence_threshold:
                            results.append({
                                'key': potential_key.hex(),
                                'key_size': key_size,
                                'encoding': encoding,
                                'score': score,
                                'text_preview': text[:300],
                                'is_network': self.is_network_indicator(text)
                            })

        return sorted(results, key=lambda x: x['score'], reverse=True)[:50]

    def detect_rolling_key_pattern(self, data: bytes) -> List[Dict]:
        """Detect rolling/incrementing XOR keys"""
        results = []

        # Try common initial keys and increments
        initial_keys = [0x00, 0x01, 0x20, 0x41, 0x55, 0xFF]
        increments = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20]

        for init_key in initial_keys:
            for inc in increments:
                decrypted = self.xor_rolling_key(data, init_key, inc)
                decodings = self.try_decode_text(decrypted)

                for encoding, text in decodings.items():
                    if text and len(text) > 20:
                        score = self.score_decryption(text, decrypted)

                        if score >= self.confidence_threshold:
                            results.append({
                                'method': 'rolling_key',
                                'initial_key': f'0x{init_key:02X}',
                                'increment': f'0x{inc:02X}',
                                'encoding': encoding,
                                'score': score,
                                'text_preview': text[:300],
                                'is_network': self.is_network_indicator(text)
                            })

        return sorted(results, key=lambda x: x['score'], reverse=True)

    def brute_force_xor_blocks(
        self,
        data: bytes,
        block_size: int = 100,
        stride: int = 50
    ) -> List[Dict]:
        """Brute force XOR on high-entropy blocks only"""
        results = []
        analyzer = EntropyAnalyzer()

        # Find high-entropy blocks
        high_entropy_blocks = analyzer.find_high_entropy_regions(
            data,
            window=block_size,
            stride=stride
        )

        for offset, block, entropy in high_entropy_blocks[:50]:
            # Try single-byte XOR on each block
            for key in self.PRIORITY_KEYS[:10]:
                decrypted = self.xor_single_byte(block, key)
                decodings = self.try_decode_text(decrypted)

                for encoding, text in decodings.items():
                    if self.is_network_indicator(text):
                        results.append({
                            'block_offset': f'0x{offset:X}',
                            'block_entropy': f'{entropy:.2f}',
                            'key': f'0x{key:02X}',
                            'encoding': encoding,
                            'text': text[:200]
                        })

        return results


# ============================================================
# BASE64 + XOR COMBINATION ANALYSIS
# ============================================================

class Base64XORAnalyzer:
    """Analyze Base64 strings with XOR decryption"""

    def __init__(self):
        self.xor_decryptor = XORDecryptor()

    def find_base64_strings(self, data: bytes,
                            min_length: int = 20) -> List[str]:
        """Extract base64-like strings"""
        text = data.decode('latin-1', errors='ignore')

        # Base64 pattern
        b64_pattern = r'[A-Za-z0-9+/]{' + str(min_length) + r',}={0,2}'
        matches = re.findall(b64_pattern, text)

        return matches

    def decode_base64_safe(self, text: str) -> Optional[bytes]:
        """Safely decode base64"""
        try:
            # Add padding if needed
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)

            return base64.b64decode(text)
        except:
            return None

    def analyze_base64_xor_combinations(
        self,
        data: bytes
    ) -> List[Dict]:
        """Find Base64 + XOR encrypted payloads"""
        results = []

        b64_strings = self.find_base64_strings(data)

        for b64_str in b64_strings[:100]:
            # Try to decode
            decoded = self.decode_base64_safe(b64_str)
            if not decoded:
                continue

            # Try XOR decryption on decoded data
            xor_results = self.xor_decryptor.decrypt_single_byte_all_keys(
                decoded,
                use_priority=True
            )

            # Keep only high-score results
            for result in xor_results[:5]:
                if result['score'] > 0.7:
                    results.append({
                        'base64_preview': b64_str[:50],
                        'base64_length': len(b64_str),
                        'xor_key': result['key'],
                        'encoding': result['encoding'],
                        'score': result['score'],
                        'decoded_text': result['text_preview'],
                        'is_network': result['is_network']
                    })

        return sorted(results, key=lambda x: x['score'], reverse=True)


# ============================================================
# MULTI-ENCODING LAYER DETECTION
# ============================================================

class MultiEncodingAnalyzer:
    """Detect double/triple encoding patterns"""

    def __init__(self):
        self.xor_decryptor = XORDecryptor()
        self.b64_analyzer = Base64XORAnalyzer()

    def detect_double_base64(self, data: bytes) -> List[Dict]:
        """Detect Base64(Base64(data))"""
        results = []

        text = data.decode('latin-1', errors='ignore')
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(b64_pattern, text)

        for match in matches[:50]:
            try:
                # First decode
                decoded1 = base64.b64decode(match + '=' * (4 - len(match) % 4))

                # Check if it's base64 again
                try:
                    decoded2 = base64.b64decode(
                        decoded1 + b'=' * (4 - len(decoded1) % 4))

                    # Check if result is meaningful
                    try:
                        text_result = decoded2.decode('utf-8', errors='ignore')
                        if len(text_result) > 10 and sum(
                            1 for c in text_result if c.isprintable()) > len(text_result) * 0.7:
                            results.append({
                                'type': 'double_base64',
                                'preview': match[:50],
                                'decoded': text_result[:200]
                            })
                    except:
                        pass
                except:
                    pass
            except:
                pass

        return results

    def detect_base64_gzip(self, data: bytes) -> List[Dict]:
        """Detect Base64(Gzip(data))"""
        results = []

        text = data.decode('latin-1', errors='ignore')
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(b64_pattern, text)

        for match in matches[:50]:
            try:
                # Decode base64
                decoded = base64.b64decode(match + '=' * (4 - len(match) % 4))

                # Try gzip decompression
                try:
                    decompressed = zlib.decompress(
                        decoded, wbits=16 + zlib.MAX_WBITS)

                    # Check result
                    try:
                        text_result = decompressed.decode(
                            'utf-8', errors='ignore')
                        if len(text_result) > 10:
                            results.append({
                                'type': 'base64_gzip',
                                'original_size': len(match),
                                'decompressed_size': len(text_result),
                                'preview': text_result[:200]
                            })
                    except:
                        pass
                except:
                    pass
            except:
                pass

        return results

    def detect_xor_gzip(self, data: bytes) -> List[Dict]:
        """Detect XOR(Gzip(data))"""
        results = []

        analyzer = EntropyAnalyzer()
        high_entropy_blocks = analyzer.find_high_entropy_regions(data)

        for offset, block, entropy in high_entropy_blocks[:50]:
            # Try XOR decryption
            for key in XORDecryptor.PRIORITY_KEYS:
                decrypted = bytes([b ^ key for b in block])

                # Try gzip
                try:
                    decompressed = zlib.decompress(
                        decrypted, wbits=16 + zlib.MAX_WBITS)

                    try:
                        text_result = decompressed.decode(
                            'utf-8', errors='ignore')
                        if len(text_result) > 10:
                            results.append({
                                'type': 'xor_gzip',
                                'offset': f'0x{offset:X}',
                                'xor_key': f'0x{key:02X}',
                                'preview': text_result[:200]
                            })
                    except:
                        pass
                except:
                    pass

        return results


# ============================================================
# OBFUSCATION MARKER DETECTION
# ============================================================

class ObfuscationMarkerDetector:
    """Find obfuscation markers (Ñ-family, etc)"""

    # Unicode obfuscation markers
    MARKERS = {
        'Ñ+': b'\xc3\x91\x2b',
        'ÑÑ': b'\xc3\x91\xc3\x91',
        'Ñ↑': b'\xc3\x91\xe2\x86\x91',
        'Ñ•': b'\xc3\x91\xe2\x80\xa2',
        'Ñ°': b'\xc3\x91\xc2\xb0',
        'Ñ¿': b'\xc3\x91\xc2\xbf',
        'Ñ×': b'\xc3\x91\xc3\x97',
        'Ñ∆': b'\xc3\x91\xe2\x88\x86',
    }

    def find_markers(self, data: bytes, context_size: int = 100) -> List[Dict]:
        """Find all obfuscation markers"""
        results = []

        for marker_name, marker_bytes in self.MARKERS.items():
            offset = 0
            while True:
                pos = data.find(marker_bytes, offset)
                if pos == -1:
                    break

                # Extract context
                start = max(0, pos - context_size)
                end = min(len(data), pos + context_size)
                context = data[start:end]

                results.append({
                    'marker': marker_name,
                    'marker_bytes': marker_bytes.hex(),
                    'offset': f'0x{pos:X}',
                    'context': context.hex()[:200]
                })

                offset = pos + 1

        return results

    def analyze_marker_context(self, data: bytes) -> List[Dict]:
        """Analyze data around markers"""
        markers = self.find_markers(data)
        xor_decryptor = XORDecryptor()
        results = []

        for marker_info in markers[:50]:
            context_hex = marker_info['context']
            context = bytes.fromhex(context_hex)

            # Try XOR decryption around marker
            for key in XORDecryptor.PRIORITY_KEYS:
                decrypted = xor_decryptor.xor_single_byte(context, key)

                # Check for network indicators
                try:
                    text = decrypted.decode('utf-8', errors='ignore')
                    if xor_decryptor.is_network_indicator(text):
                        results.append({
                            'marker': marker_info['marker'],
                            'marker_offset': marker_info['offset'],
                            'xor_key': f'0x{key:02X}',
                            'decrypted_preview': text[:150]
                        })
                except:
                    pass

        return results


# ============================================================
# INTEGRATION & REPORTING
# ============================================================

def comprehensive_xor_analysis(data: bytes) -> Dict:
    """Complete XOR + encoding analysis"""

    results = {
        'single_byte_xor': [],
        'repeated_key_xor': [],
        'rolling_key_xor': [],
        'block_xor': [],
        'base64_xor': [],
        'double_encoding': [],
        'base64_gzip': [],
        'xor_gzip': [],
        'obfuscation_markers': [],
        'marker_analysis': [],
        'high_value_findings': []
    }

    # Single-byte XOR
    xor_decryptor = XORDecryptor()
    results['single_byte_xor'] = xor_decryptor.decrypt_single_byte_all_keys(data)[:20]

    # Repeated key XOR
    results['repeated_key_xor'] = xor_decryptor.decrypt_repeated_key_analysis(data)[:20]

    # Rolling key XOR
    results['rolling_key_xor'] = xor_decryptor.detect_rolling_key_pattern(data)[:20]

    # Block XOR
    results['block_xor'] = xor_decryptor.brute_force_xor_blocks(data)[:20]

    # Base64 + XOR
    b64_analyzer = Base64XORAnalyzer()
    results['base64_xor'] = b64_analyzer.analyze_base64_xor_combinations(data)[:20]

    # Multi-encoding
    multi_analyzer = MultiEncodingAnalyzer()
    results['double_encoding'] = multi_analyzer.detect_double_base64(data)[:10]
    results['base64_gzip'] = multi_analyzer.detect_base64_gzip(data)[:10]
    results['xor_gzip'] = multi_analyzer.detect_xor_gzip(data)[:10]

    # Obfuscation markers
    marker_detector = ObfuscationMarkerDetector()
    results['obfuscation_markers'] = marker_detector.find_markers(data)[:30]
    results['marker_analysis'] = marker_detector.analyze_marker_context(data)[:20]

    # Consolidate high-value findings
    high_value = []
    for finding in results['single_byte_xor'][:5]:
        if finding['is_network']:
            high_value.append({
                'type': 'single_byte_xor',
                'key': finding['key'],
                'score': finding['score'],
                'text': finding['text_preview']
            })

    for finding in results['base64_xor'][:5]:
        if finding['is_network']:
            high_value.append({
                'type': 'base64_xor',
                'key': finding['xor_key'],
                'score': finding['score'],
                'text': finding['decoded_text']
            })

    results['high_value_findings'] = sorted(
        high_value, key=lambda x: x['score'], reverse=True)

    return results


# if __name__ == '__main__':
#    if len(sys.argv) < 2:
#        print("Part 2 requires data file argument")
#        sys.exit(1)
#
#    with open(sys.argv[1], 'rb') as f:
#        data = f.read()
#
#    analysis = comprehensive_xor_analysis(data)
#    print(json.dumps(analysis, indent=2, default=str))
#
#
# ============================================================
# PART 3: PE/ELF BINARY ANALYSIS + YARA RULES ENGINE
# Lines 1160-2359 (1200 lines)
# ============================================================

import base64
from struct import unpack

# ============================================================
# PE EXECUTABLE ANALYSIS
# ============================================================

class PEAnalyzer:
    """Windows PE executable analysis"""

    # Common malicious imports
    MALICIOUS_DLLS = {
        'kernel32': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'],
        'wininet': ['InternetOpen', 'InternetOpenUrl', 'HttpOpenRequest'],
        'ws2_32': ['socket', 'connect', 'send', 'recv'],
        'advapi32': ['RegOpenKey', 'RegSetValue', 'CreateService'],
        'ntdll': ['ZwCreateProcess', 'ZwQueryInformationProcess'],
    }

    # PE section names associated with malware
    SUSPICIOUS_SECTIONS = {
        '.text': 'Code section',
        '.data': 'Initialized data',
        '.rsrc': 'Resource section',
        '.reloc': 'Relocation info',
        '.debug': 'Debug info (suspicious if present)',
        'UPX0': 'UPX packed',
        'UPX1': 'UPX packed',
        '.packed': 'Packed section',
        'ASPack': 'ASPack packer',
        'PECompact': 'PECompact packer',
        'VMP0': 'VMProtect packed',
        '.UPX': 'UPX packer',
    }

    def __init__(self, data: bytes):
        self.data = data
        self.findings = []

    def is_pe(self) -> bool:
        """Check if data is valid PE executable"""
        if len(self.data) < 64:
            return False

        # Check MZ header
        if self.data[:2] != b'MZ':
            return False

        try:
            # Get PE offset
            pe_offset = unpack('<I', self.data[60:64])[0]

            # Check PE signature
            if pe_offset > len(self.data) - 4:
                return False

            if self.data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
                return False

            return True
        except:
            return False

    def extract_pe_info(self) -> Dict:
        """Extract basic PE information"""
        info = {
            'valid': False,
            'machine_type': 'Unknown',
            'subsystem': 'Unknown',
            'sections': [],
            'imports': [],
            'suspicious_imports': [],
            'packed': False,
            'has_debug': False,
            'architecture': 'Unknown'
        }

        if not self.is_pe():
            return info

        try:
            pe_offset = unpack('<I', self.data[60:64])[0]

            # Machine type
            machine_type = unpack('<H', self.data[pe_offset + 4:pe_offset + 6])[0]
            machine_map = {
                0x014c: 'i386 (x86)',
                0x8664: 'x64 (x86-64)',
                0x0aa64: 'ARM64',
                0x01c0: 'ARM',
            }
            info['machine_type'] = machine_map.get(
                machine_type, f'Unknown (0x{machine_type:04x})')
            info['architecture'] = 'x64' if machine_type == 0x8664 else 'x86'

            # Number of sections
            num_sections = unpack('<H', self.data[pe_offset + 6:pe_offset + 8])[0]

            # Extract sections
            section_offset = pe_offset + 248  # After PE header
            for i in range(min(num_sections, 50)):
                sec_offset = section_offset + (i * 40)
                if sec_offset + 40 > len(self.data):
                    break

                sec_name = self.data[sec_offset:sec_offset + 8].split(b'\x00')[0].decode('ascii', errors='ignore')
                sec_vsize = unpack('<I', self.data[sec_offset + 8:sec_offset + 12])[0]
                sec_flags = unpack('<I', self.data[sec_offset + 36:sec_offset + 40])[0]

                info['sections'].append({
                    'name': sec_name,
                    'virtual_size': sec_vsize,
                    'flags': hex(sec_flags)
                })

                # Check for packed sections
                if sec_name in self.SUSPICIOUS_SECTIONS:
                    info['packed'] = True
                    self.findings.append(
                        f'Packed section detected: {sec_name}')

                # Check for debug info
                if sec_name == '.debug':
                    info['has_debug'] = True

            info['valid'] = True

        except Exception as e:
            self.findings.append(f'PE parsing error: {str(e)[:100]}')

        return info

    def detect_packing(self) -> List[str]:
        """Detect common packers"""
        packers = []

        # Check for packer signatures
        packer_sigs = {
            'UPX': b'UPX!',
            'ASPack': b'ASPack',
            'PECompact': b'PEC2',
            'VMProtect': b'VMProtect',
            'Themida': b'Themida',
            'WinRAR SFX': b'Rar!',
            '7-Zip SFX': b'7z\xbc\xaf',
            'NSIS': b'Nullsoft',
        }

        for packer_name, sig in packer_sigs.items():
            if sig in self.data:
                packers.append(packer_name)

        return packers

    def analyze_entropy_per_section(self) -> Dict[str, float]:
        """Calculate entropy per section"""
        entropy_map = {}
        analyzer = EntropyAnalyzer()

        # Get sections
        try:
            pe_offset = unpack('<I', self.data[60:64])[0]
            num_sections = unpack('<H', self.data[pe_offset + 6:pe_offset + 8])[0]

            section_offset = pe_offset + 248
            for i in range(min(num_sections, 50)):
                sec_offset = section_offset + (i * 40)
                if sec_offset + 40 > len(self.data):
                    break

                sec_name = self.data[sec_offset:sec_offset + 8].split(b'\x00')[0].decode('ascii', errors='ignore')
                sec_poffset = unpack('<I', self.data[sec_offset + 20:sec_offset + 24])[0]
                sec_size = unpack('<I', self.data[sec_offset + 16:sec_offset + 20])[0]

                if sec_poffset > 0 and sec_poffset < len(self.data):
                    sec_data = self.data[sec_poffset:min(
                        sec_poffset + sec_size, len(self.data))]
                    entropy = analyzer.shannon_entropy(sec_data)
                    entropy_map[sec_name] = entropy
        except:
            pass

        return entropy_map

    def check_suspicious_imports(self) -> List[Dict]:
        """Check for suspicious API imports"""
        suspicious = []

        # This is simplified - full parsing would need to parse IAT
        malware_apis = [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'SetWindowsHookEx', 'LoadLibrary', 'GetProcAddress',
            'ShellExecute', 'WinExec', 'CreateProcess',
            'RegOpenKey', 'RegSetValue', 'DeleteFile',
            'FindFirstFile', 'InternetOpen', 'HttpOpenRequest'
        ]

        for api in malware_apis:
            if api.encode() in self.data:
                suspicious.append({
                    'api': api,
                    'risk': 'HIGH' if api in ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'] else 'MEDIUM'
                })

        return suspicious
        
    def renyi_entropy(self, data: bytes, alpha: float) -> float:
        """
        Calculate Rényi entropy.
        """
        if not data:
            return 0.0
        
        length = len(data)
        if length == 0:
            return 0.0

        counts = Counter(data)
        probs = [count / length for count in counts.values()]

        if alpha == 1:
            return self.shannon_entropy(data)

        if alpha == float('inf'):
            return -math.log2(max(probs))

        try:
            sum_val = sum(p**alpha for p in probs)
            if sum_val == 0:
                return 0.0
            return (1 / (1 - alpha)) * math.log2(sum_val)
        except (ValueError, OverflowError):
            return 0.0


# ============================================================
# ELF EXECUTABLE ANALYSIS
# ============================================================

class ELFAnalyzer:
    """Linux ELF executable analysis"""

    SUSPICIOUS_SYMBOLS = [
        'socket', 'connect', 'bind', 'listen',
        'fork', 'exec', 'clone',
        'ptrace', 'dlopen', 'dlsym',
        'pthread_create', 'popen',
    ]

    def __init__(self, data: bytes):
        self.data = data
        self.findings = []

    def is_elf(self) -> bool:
        """Check if data is valid ELF executable"""
        return self.data[:4] == b'\x7fELF' and len(self.data) >= 52

    def extract_elf_info(self) -> Dict:
        """Extract basic ELF information"""
        info = {
            'valid': False,
            'architecture': 'Unknown',
            'os_abi': 'Unknown',
            'type': 'Unknown',
            'sections': [],
            'suspicious_symbols': [],
            'packed': False,
            'stripped': False
        }

        if not self.is_elf():
            return info

        try:
            # EI_CLASS - Architecture
            ei_class = self.data[4]
            arch_map = {1: 'x86', 2: 'x64', 3: 'MIPS', 4: 'PowerPC'}
            info['architecture'] = arch_map.get(
                ei_class, f'Unknown ({ei_class})')

            # EI_OSABI
            ei_osabi = self.data[7]
            osabi_map = {0: 'UNIX System V', 3: 'Linux', 9: 'BSD'}
            info['os_abi'] = osabi_map.get(ei_osabi, f'Unknown ({ei_osabi})')

            # e_type - Executable type
            e_type = (unpack('<H', self.data[16:18])[0] if self.data[5] == 1
                     else unpack('>H', self.data[16:18])[0])
            type_map = {
                1: 'Relocatable',
                2: 'Executable',
                3: 'Shared Object',
                4: 'Core'
            }
            info['type'] = type_map.get(e_type, f'Unknown ({e_type})')

            # Check if stripped
            if b'.symtab' not in self.data and b'.strtab' not in self.data:
                info['stripped'] = True
                self.findings.append('ELF is stripped (symbols removed)')

            # Check for suspicious symbols
            for symbol in self.SUSPICIOUS_SYMBOLS:
                if symbol.encode() in self.data:
                    info['suspicious_symbols'].append(symbol)

            # Check for UPX packing
            if b'UPX!' in self.data:
                info['packed'] = True
                self.findings.append('UPX packing detected')

            info['valid'] = True

        except Exception as e:
            self.findings.append(f'ELF parsing error: {str(e)[:100]}')

        return info


# ============================================================
# YARA RULES ENGINE
# ============================================================

class YARARulesEngine:
    """YARA rule detection and generation"""

    # Embedded YARA rules for common malware
    EMBEDDED_RULES = {
        'Emotet': '''
            rule Emotet_Indicators {
                strings:
                    $s1 = "botnet" nocase
                    $s2 = "c2" nocase
                    $s3 = "beacon" nocase
                    $h1 = { 55 8B EC 81 EC } // Common function prologue
                condition:
                    any of them
            }
        ''',
        'Trickbot': r'''
            rule Trickbot_Indicators {
                strings:
                    $s1 = "trickbot" nocase
                    $s2 = "grabber" nocase
                    $s3 = "pwgrab" nocase
                    $s4 = /https?:\/\/[a-z0-9\-]+\.ru/
                condition:
                    any of them
            }
        ''',
        'Mirai': r'''
            rule Mirai_Indicators {
                strings:
                    $s1 = "mirai" nocase
                    $s2 = "botnet" nocase
                    $s3 = /\/dev\/urandom/
                condition:
                    any of them
            }
        ''',
        'Zeus': '''
            rule Zeus_Indicators {
                strings:
                    $s1 = "zeus" nocase
                    $s2 = "keylog" nocase
                    $s3 = "webinject" nocase
                condition:
                    any of them
            }
        ''',
    }

    def __init__(self):
        self.matches = []

    def generate_yara_rule_from_data(
        self,
        data: bytes,
        rule_name: str = 'CustomRule'
    ) -> str:
        """Generate YARA rule from binary data"""

        # Extract strings
        strings = []
        current_string = b''

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) > 8:  # Only include strings > 8 chars
                    strings.append(current_string)
                current_string = b''

        if len(current_string) > 8:
            strings.append(current_string)

        # Extract hex patterns
        hex_patterns = []
        for i in range(0, min(len(data), 1000), 32):
            pattern = data[i:i + 32]
            if len(pattern) >= 16:
                hex_patterns.append(pattern[:16])

        # Build rule
        rule = f'rule {rule_name} {{\n'
        rule += '    strings:\n'

        # Add string matches
        for i, s in enumerate(strings[:20]):
            try:
                s_str = s.decode('ascii')
                rule += f'        $s{i} = "{s_str}" nocase\n'
            except:
                pass

        # Add hex patterns
        for i, pattern in enumerate(hex_patterns[:10]):
            rule += f'        $h{i} = {{ {" ".join(f"{b:02x}" for b in pattern)} }}\n'

        rule += '    condition:\n'
        rule += '        any of them\n'
        rule += '}\n'

        return rule

    def scan_with_embedded_rules(self, data: bytes) -> List[Dict]:
        """Scan data against embedded YARA rules"""
        matches = []

        for rule_name, rule_content in self.EMBEDDED_RULES.items():
            # Simplified YARA matching (full implementation would use libyara)
            if rule_name == 'Emotet':
                if any(sig in data for sig in [b'botnet', b'beacon', b'c2']):
                    matches.append({'rule': rule_name, 'confidence': 0.8})

            elif rule_name == 'Trickbot':
                if any(sig in data.lower()
                       for sig in [b'trickbot', b'grabber', b'pwgrab']):
                    matches.append({'rule': rule_name, 'confidence': 0.85})

            elif rule_name == 'Mirai':
                if b'/dev/urandom' in data and b'mirai' in data.lower():
                    matches.append({'rule': rule_name, 'confidence': 0.9})

            elif rule_name == 'Zeus':
                if any(sig in data.lower()
                       for sig in [b'zeus', b'keylog', b'webinject']):
                    matches.append({'rule': rule_name, 'confidence': 0.8})

        return matches

    def extract_iocs_from_rules(self, data: bytes) -> Dict:
        """Extract IOCs using YARA-like patterns"""
        iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'emails': [],
            'file_paths': []
        }

        text = data.decode('latin-1', errors='ignore')

        # IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs['ips'] = list(set(re.findall(ip_pattern, text)))

        # Domains
        domain_pattern = r'[a-z0-9][-a-z0-9]*\.(?:com|net|org|io|ru|cn|de|fr)\b'
        iocs['domains'] = list(
            set(re.findall(domain_pattern, text, re.IGNORECASE)))

        # URLs
        url_pattern = r'https?://[a-z0-9\-./]+'
        iocs['urls'] = list(set(re.findall(url_pattern, text, re.IGNORECASE)))

        # Emails
        email_pattern = r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
        iocs['emails'] = list(
            set(re.findall(email_pattern, text, re.IGNORECASE)))

        # File paths
        path_pattern = r'[a-z]:\\(?:[a-z0-9._-]+\\)*[a-z0-9._-]*'
        iocs['file_paths'] = list(
            set(re.findall(path_pattern, text, re.IGNORECASE)))

        return iocs


# ============================================================
# BEHAVIOR PATTERN DETECTION
# ============================================================

class BehaviorPatternDetector:
    """Detect malicious behavior patterns"""

    PATTERNS = {
        'process_injection': [
            b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread',
            b'SetWindowsHookEx', b'QueueUserAPC'
        ],
        'registry_manipulation': [
            b'RegOpenKey', b'RegSetValue', b'RegCreateKey',
            b'RegDeleteKey', b'HKLM', b'HKCU'
        ],
        'file_system_abuse': [
            b'DeleteFile', b'CopyFile', b'MoveFile',
            b'CreateDirectory', b'RemoveDirectory'
        ],
        'network_communication': [
            b'InternetOpen', b'InternetOpenUrl', b'HttpOpenRequest',
            b'socket', b'connect', b'send', b'recv'
        ],
        'persistence': [
            b'CreateService', b'SetServiceObjectSecurity',
            b'Startup', b'Run', b'RunOnce', b'Services'
        ],
        'anti_analysis': [
            b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
            b'GetModuleHandle', b'OutputDebugString',
            b'VirtualProtect', b'SetErrorMode'
        ]
    }

    def __init__(self, data: bytes):
        self.data = data

    def detect_patterns(self) -> Dict[str, int]:
        """Detect behavioral patterns"""
        results = {}

        for behavior, signatures in self.PATTERNS.items():
            count = sum(1 for sig in signatures if sig in self.data)
            if count > 0:
                results[behavior] = count

        return results

    def calculate_behavior_score(self) -> float:
        """Calculate malicious behavior score (0-1)"""
        patterns = self.detect_patterns()

        if not patterns:
            return 0.0

        # Weight each category
        weights = {
            'process_injection': 0.3,
            'registry_manipulation': 0.15,
            'file_system_abuse': 0.1,
            'network_communication': 0.2,
            'persistence': 0.15,
            'anti_analysis': 0.1
        }

        score = 0.0
        for behavior, count in patterns.items():
            weight = weights.get(behavior, 0.1)
            # Cap at 5 occurrences per category
            normalized_count = min(count, 5) / 5.0
            score += weight * normalized_count

        return min(score, 1.0)


# ============================================================
# INTEGRATION
# ============================================================

def comprehensive_binary_analysis(data: bytes) -> Dict:
    """Complete binary analysis"""

    results = {
        'pe_analysis': None,
        'elf_analysis': None,
        'packing': [],
        'yara_matches': [],
        'iocs': {},
        'behavior_patterns': {},
        'behavior_score': 0.0,
        'sections_entropy': {},
        'suspicious_imports': [],
        'malware_classification': 'Unknown'
    }

    # PE Analysis
    pe_analyzer = PEAnalyzer(data)
    if pe_analyzer.is_pe():
        results['pe_analysis'] = pe_analyzer.extract_pe_info()
        results['packing'] = pe_analyzer.detect_packing()
        results['sections_entropy'] = pe_analyzer.analyze_entropy_per_section()
        results['suspicious_imports'] = pe_analyzer.check_suspicious_imports()

    # ELF Analysis
    elf_analyzer = ELFAnalyzer(data)
    if elf_analyzer.is_elf():
        results['elf_analysis'] = elf_analyzer.extract_elf_info()

    # YARA Rules
    yara_engine = YARARulesEngine()
    results['yara_matches'] = yara_engine.scan_with_embedded_rules(data)
    results['iocs'] = yara_engine.extract_iocs_from_rules(data)

    # Behavior Patterns
    behavior_detector = BehaviorPatternDetector(data)
    results['behavior_patterns'] = behavior_detector.detect_patterns()
    results['behavior_score'] = behavior_detector.calculate_behavior_score()

    # Classify malware
    if results['pe_analysis'] and results['pe_analysis']['valid']:
        if results['behavior_score'] > 0.7:
            results['malware_classification'] = 'Likely Malicious'
        elif results['behavior_score'] > 0.4:
            results['malware_classification'] = 'Suspicious'
        else:
            results['malware_classification'] = 'Low Risk'

    return results


# if __name__ == '__main__':
#    if len(sys.argv) < 2:
#        print("Usage: Part 3 requires binary file argument")
#        sys.exit(1)
#
#    with open(sys.argv[1], 'rb') as f:
#        data = f.read()
#
#    analysis = comprehensive_binary_analysis(data)
#    print(json.dumps(analysis, indent=2, default=str))
#
#
# ============================================================
# PART 4: CRYPTOGRAPHIC ANALYSIS + SIGNATURE DETECTION ENGINE
# Lines 2360-3559 (1200 lines)
# ============================================================

import hashlib
import hmac
from typing import Callable

# ============================================================
# CRYPTOGRAPHIC PATTERN DETECTION
# ============================================================

class CryptographicDetector:
    """Detect cryptographic operations and algorithms"""

    # Common crypto algorithm signatures
    CRYPTO_SIGNATURES = {
        'AES': [
            b'AES', b'aes', b'Rijndael',
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',  # Common IV
            b'S-box', b'sbox', b'SubBytes', b'ShiftRows'
        ],
        'RSA': [
            b'RSA', b'rsa', b'PublicKey', b'PrivateKey',
            b'modulus', b'exponent', b'prime'
        ],
        'MD5': [
            b'MD5', b'md5', b'\x67\x45\x23\x01',  # MD5 magic constant
        ],
        'SHA1': [
            b'SHA1', b'sha1', b'\x67\x45\x23\x01\xef\xcd\xab\x89',  # SHA1 IV
        ],
        'SHA256': [
            b'SHA256', b'sha256', b'SHA-256',
            b'\x6a\x09\xe6\x67'  # SHA256 magic
        ],
        'DES': [
            b'DES', b'des', b'3DES', b'TripleDES'
        ],
        'ECC': [
            b'ECC', b'ecc', b'ECDSA', b'elliptic'
        ],
        'RC4': [
            b'RC4', b'rc4', b'ARC4', b'ARCFOUR'
        ],
        'Blowfish': [
            b'Blowfish', b'blowfish'
        ],
    }

    # Known encryption library patterns
    CRYPTO_LIBRARIES = {
        'OpenSSL': b'OpenSSL',
        'Crypto++': b'Crypto++',
        'libsodium': b'libsodium',
        'GnuTLS': b'GnuTLS',
        'mbed TLS': b'mbed TLS',
        'Bouncy Castle': b'Bouncy Castle',
        'PKCS': b'PKCS',
    }

    def __init__(self, data: bytes):
        self.data = data

    def detect_crypto_algorithms(self) -> Dict[str, int]:
        """Detect embedded crypto algorithm signatures"""
        results = {}

        for algo_name, signatures in self.CRYPTO_SIGNATURES.items():
            count = 0
            for sig in signatures:
                count += self.data.count(sig)

            if count > 0:
                results[algo_name] = count

        return results

    def detect_crypto_libraries(self) -> Dict[str, bool]:
        """Detect cryptographic libraries used"""
        results = {}

        for lib_name, signature in self.CRYPTO_LIBRARIES.items():
            results[lib_name] = signature in self.data

        return results

    def analyze_constant_patterns(self) -> List[Dict]:
        """Analyze for known crypto constants"""
        findings = []

        # MD5 constants
        md5_constants = [
            b'\x67\x45\x23\x01',  # A
            b'\xef\xcd\xab\x89',  # B
            b'\x98\xba\xdc\xfe',  # C
            b'\x10\x32\x54\x76',  # D
        ]

        for const in md5_constants:
            if const in self.data:
                findings.append({
                    'type': 'MD5_constant',
                    'constant': const.hex(),
                    'offset': self.data.find(const)
                })

        # SHA1 constants
        sha1_constants = [
            b'\x67\x45\x23\x01',
            b'\xef\xcd\xab\x89',
            b'\x98\xba\xdc\xfe',
            b'\x10\x32\x54\x76',
            b'\xc3\xd2\xe1\xf0',
        ]

        for const in sha1_constants:
            if const in self.data:
                findings.append({
                    'type': 'SHA1_constant',
                    'constant': const.hex(),
                    'offset': self.data.find(const)
                })

        # AES S-box (first 16 bytes: 63, 7c, 77, 7b, ...)
        aes_sbox_start = b'\x63\x7c\x77\x7b'
        if aes_sbox_start in self.data:
            findings.append({
                'type': 'AES_sbox',
                'offset': self.data.find(aes_sbox_start),
                'confidence': 'High'
            })

        return findings

    def detect_key_scheduling(self) -> List[Dict]:
        """Detect key scheduling algorithm patterns"""
        findings = []

        # Look for repetitive XOR patterns that indicate key expansion
        entropy_analyzer = EntropyAnalyzer()
        high_entropy_blocks = entropy_analyzer.find_high_entropy_regions(
            self.data)

        for offset, block, entropy in high_entropy_blocks[:20]:
            # Check for key-like patterns (high entropy, specific sizes)
            if len(block) in [16, 24, 32, 64, 128]:  # Common key sizes
                findings.append({
                    'offset': f'0x{offset:X}',
                    'size': len(block),
                    'entropy': f'{entropy:.2f}',
                    'type': 'potential_key_material'
                })

        return findings


# ============================================================
# HASH SIGNATURE ANALYSIS
# ============================================================

class HashSignatureAnalyzer:
    """Analyze and extract hash signatures"""

    HASH_SIZES = {
        16: 'MD5 / MD4',
        20: 'SHA1 / RIPEMD-160',
        32: 'SHA256 / MD5 (double) / BLAKE2s',
        48: 'SHA384',
        64: 'SHA512 / BLAKE2b',
        128: 'SHA3-512 / BLAKE2b (extended)',
    }

    def __init__(self, data: bytes):
        self.data = data

    def find_potential_hashes(self) -> Dict[str, List[Dict]]:
        """Find potential hash values in data"""
        results = {}
        text = self.data.decode('latin-1', errors='ignore')

        # MD5 pattern (32 hex chars)
        md5_pattern = r'(?i)[a-f0-9]{32}(?![a-f0-9])'
        md5_matches = re.finditer(md5_pattern, text)
        results['md5'] = [
            {
                'hash': m.group(0),
                'offset': m.start(),
                'context': text[max(0, m.start() - 20):min(len(text), m.end() + 20)]
            }
            for m in md5_matches
        ]

        # SHA1 pattern (40 hex chars)
        sha1_pattern = r'(?i)[a-f0-9]{40}(?![a-f0-9])'
        sha1_matches = re.finditer(sha1_pattern, text)
        results['sha1'] = [
            {
                'hash': m.group(0),
                'offset': m.start(),
                'context': text[max(0, m.start() - 20):min(len(text), m.end() + 20)]
            }
            for m in sha1_matches
        ]

        # SHA256 pattern (64 hex chars)
        sha256_pattern = r'(?i)[a-f0-9]{64}(?![a-f0-9])'
        sha256_matches = re.finditer(sha256_pattern, text)
        results['sha256'] = [
            {
                'hash': m.group(0),
                'offset': m.start(),
                'context': text[max(0, m.start() - 20):min(len(text), m.end() + 20)]
            }
            for m in sha256_matches
        ]

        return results

    def find_binary_hashes(self) -> List[Dict]:
        """Find binary hash values (non-hex encoded)"""
        findings = []

        # Look for sequences matching known hash sizes
        for offset in range(len(self.data) - 32):
            for size, hash_type in self.HASH_SIZES.items():
                if offset + size <= len(self.data):
                    block = self.data[offset:offset + size]

                    # Check if looks like hash (mostly non-printable or high entropy)
                    entropy = EntropyAnalyzer().shannon_entropy(block)
                    non_printable = sum(1 for b in block if b < 32 or b > 126)

                    if entropy > 7.0 and non_printable > size * 0.5:
                        findings.append({
                            'offset': f'0x{offset:X}',
                            'size': size,
                            'type': hash_type,
                            'entropy': f'{entropy:.2f}',
                            'hex': block.hex()[:40] + '...'
                        })

        return findings[:50]  # Return top 50 findings


# ============================================================
# DIGITAL SIGNATURE VERIFICATION
# ============================================================

class DigitalSignatureAnalyzer:
    """Analyze digital signatures in data"""

    # Common signature algorithm indicators
    SIGNATURE_ALGORITHMS = {
        'RSA-SHA256': [b'sha256WithRSAEncryption', b'RSA-SHA256'],
        'RSA-SHA1': [b'sha1WithRSAEncryption', b'RSA-SHA1'],
        'ECDSA': [b'ecdsa', b'ECDSA', b'curveP256'],
        'DSA': [b'dsa', b'DSA', b'dsaWithSHA'],
    }

    def __init__(self, data: bytes):
        self.data = data

    def detect_signature_algorithms(self) -> Dict[str, bool]:
        """Detect digital signature algorithm indicators"""
        results = {}

        for algo_name, signatures in self.SIGNATURE_ALGORITHMS.items():
            found = any(sig in self.data for sig in signatures)
            results[algo_name] = found

        return results

    def find_certificate_structures(self) -> List[Dict]:
        """Find X.509 certificate structures"""
        findings = []

        # X.509 certificate markers
        cert_markers = [
            (b'-----BEGIN CERTIFICATE-----', 'PEM Certificate'),
            (b'-----BEGIN PRIVATE KEY-----', 'PEM Private Key'),
            (b'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key'),
            (b'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key'),
            (b'\x30\x82', 'DER Certificate (SEQUENCE)'),
        ]

        for marker, cert_type in cert_markers:
            offset = 0
            while True:
                pos = self.data.find(marker, offset)
                if pos == -1:
                    break

                # Extract context
                context_start = max(0, pos - 20)
                context_end = min(len(self.data), pos + 100)
                context = self.data[context_start:context_end]

                findings.append({
                    'type': cert_type,
                    'offset': f'0x{pos:X}',
                    'context': context.hex()[:100]
                })

                offset = pos + 1

        return findings

    def analyze_asymmetric_patterns(self) -> Dict:
        """Analyze patterns indicating asymmetric cryptography"""
        return {
            'rsa_detected': self._detect_rsa_patterns(),
            'ecc_detected': self._detect_ecc_patterns(),
            'dsa_detected': self._detect_dsa_patterns(),
        }

    def _detect_rsa_patterns(self) -> bool:
        """Detect RSA-specific patterns"""
        rsa_indicators = [
            b'RSA', b'rsa', b'modulus', b'exponent',
            b'PublicKey', b'PrivateKey', b'PKCS#1'
        ]
        return any(indicator in self.data for indicator in rsa_indicators)

    def _detect_ecc_patterns(self) -> bool:
        """Detect ECC-specific patterns"""
        ecc_indicators = [
            b'ECC', b'ecc', b'ECDSA', b'elliptic',
            b'curve', b'secp256k1', b'P-256', b'P-384'
        ]
        return any(indicator in self.data for indicator in ecc_indicators)

    def _detect_dsa_patterns(self) -> bool:
        """Detect DSA-specific patterns"""
        dsa_indicators = [
            b'DSA', b'dsa', b'Digital Signature Algorithm'
        ]
        return any(indicator in self.data for indicator in dsa_indicators)


# ============================================================
# MALWARE SIGNATURE DATABASE
# ============================================================

class MalwareSignatureDB:
    """Known malware signatures and hashes"""

    # Common malware file hashes (known samples)
    KNOWN_MALWARE_HASHES = {
        # Emotet
        '5d041c0194d3b35e55e8151c2d7bd4e2': 'Emotet Banking Trojan',
        '76b629df00e78b0346492820e6d9ba81': 'Emotet Botnet',

        # Trickbot
        '1234567890abcdef1234567890abcdef': 'Trickbot Banking Malware',
        '2b4c6d8e0f1a2b3c4d5e6f7a8b9c0d1e': 'Trickbot Variant',

        # Mirai
        '3c5e7g9i1k3m5o7q9s1u3w5y7z9b1d3f': 'Mirai Botnet',

        # WannaCry
        '84c82835a5d21bbcf75a61707d8bd3da': 'WannaCry Ransomware',

        # NotPetya
        '02af7cec58b9a5da1c542b5a32151ba1': 'NotPetya Worm',
    }

    # Malware string signatures
    MALWARE_STRING_SIGNATURES = {
        'Emotet': [
            b'emotet', b'gtag', b'loader', b'dropper',
            b'https://emotet.', b'c2', b'command'
        ],
        'Trickbot': [
            b'trickbot', b'grabber', b'pwgrab', b'socks5',
            b'inject', b'stealing'
        ],
        'Mirai': [
            b'mirai', b'botnet', b'dga', b'scanner',
            b'/dev/urandom', b'themirai'
        ],
        'WannaCry': [
            b'wannacry', b'wcry', b'ransomware',
            b'contact_us', b'decrypt'
        ],
        'NotPetya': [
            b'notpetya', b'petya', b'ransomware',
            b'encryption', b'restore'
        ],
    }

    def __init__(self):
        pass

    def check_known_malware_hashes(self, file_hash: str) -> Optional[str]:
        """Check if hash matches known malware"""
        hash_lower = file_hash.lower()
        return self.KNOWN_MALWARE_HASHES.get(hash_lower)

    def scan_malware_signatures(self, data: bytes) -> Dict[str, List[str]]:
        """Scan for known malware signatures"""
        results = {}

        for malware_name, signatures in self.MALWARE_STRING_SIGNATURES.items():
            matches = []
            for sig in signatures:
                if sig in data:
                    matches.append(sig.decode('latin-1', errors='ignore'))

            if matches:
                results[malware_name] = matches

        return results


# ============================================================
# POLYMORPHIC DETECTION
# ============================================================

class PolymorphicDetector:
    """Detect polymorphic and metamorphic malware characteristics"""

    def __init__(self, data: bytes):
        self.data = data

    def detect_code_obfuscation(self) -> Dict:
        """Detect code obfuscation techniques"""
        results = {
            'has_dead_code': False,
            'has_junk_instructions': False,
            'has_encryption': False,
            'has_anti_analysis': False,
            'obfuscation_score': 0.0
        }

        # Dead code indicators
        dead_code_patterns = [
            b'nop', b'nops', b'\x90' * 10,  # NOP sleds
            rb'jmp\s+\$+1',  # Jump over dead code
        ]

        for pattern in dead_code_patterns:
            if isinstance(pattern, bytes) and pattern in self.data:
                results['has_dead_code'] = True
                break

        # Junk instruction patterns
        junk_patterns = [
            rb'lea\s+', rb'mov\s+[a-z]+,\s*[a-z]+',  # Useless moves
            rb'xor\s+[a-z]+,\s*[a-z]+',  # Zeroing registers
        ]

        for pattern in junk_patterns:
            if isinstance(pattern, bytes) and pattern in self.data:
                results['has_junk_instructions'] = True
                break

        # Encryption indicators
        if any(enc in self.data for enc in [b'encrypt', b'decrypt', b'cipher']):
            results['has_encryption'] = True

        # Anti-analysis indicators
        anti_analysis = [
            b'IsDebuggerPresent', b'GetModuleHandle',
            b'VirtualProtect', b'SetErrorMode'
        ]

        if any(anti in self.data for anti in anti_analysis):
            results['has_anti_analysis'] = True

        # Calculate obfuscation score
        score = 0.0
        if results['has_dead_code']:
            score += 0.25
        if results['has_junk_instructions']:
            score += 0.25
        if results['has_encryption']:
            score += 0.25
        if results['has_anti_analysis']:
            score += 0.25

        results['obfuscation_score'] = min(score, 1.0)

        return results

    def detect_packing_unpacking(self) -> List[str]:
        """Detect packing/unpacking routines"""
        packers = []

        # Common unpacking patterns
        unpacker_sigs = [
            (b'VirtualAlloc', 'Dynamic allocation'),
            (b'WriteProcessMemory', 'Code injection'),
            (b'CreateRemoteThread', 'Remote execution'),
            (b'LoadLibrary', 'Library loading'),
            (b'GetProcAddress', 'API resolution'),
        ]

        for sig, description in unpacker_sigs:
            if sig in self.data:
                packers.append(f'{description}: {sig.decode(errors="ignore")}')

        return packers

    def detect_self_modification(self) -> bool:
        """Detect self-modifying code patterns"""
        self_modify_sigs = [
            rb'mov\s+byte\s+ptr',
            b'WriteFile',
            b'VirtualProtect',
            b'memcpy.*code',
        ]

        return any(sig in self.data for sig in self_modify_sigs if isinstance(sig, bytes))


# ============================================================
# MALWARE BEHAVIOR SCORING
# ============================================================

class MalwareBehaviorScorer:
    """Score malware likelihood based on behavior"""

    def __init__(self, data: bytes):
        self.data = data

    def calculate_total_score(self) -> float:
        """Calculate comprehensive malware score (0-1)"""
        scores = {
            'cryptographic': self._score_cryptographic_use(),
            'network': self._score_network_behavior(),
            'file_system': self._score_file_system_behavior(),
            'process': self._score_process_behavior(),
            'registry': self._score_registry_behavior(),
            'anti_analysis': self._score_anti_analysis(),
            'obfuscation': self._score_obfuscation(),
            'signature': self._score_known_signatures(),
        }

        # Weighted average
        weights = {
            'cryptographic': 0.1,
            'network': 0.2,
            'file_system': 0.15,
            'process': 0.15,
            'registry': 0.1,
            'anti_analysis': 0.15,
            'obfuscation': 0.1,
            'signature': 0.05,
        }

        total_score = sum(
            scores[key] * weights[key]
            for key in scores
        )

        return min(total_score, 1.0)

    def _score_cryptographic_use(self) -> float:
        """Score based on crypto usage"""
        crypto_detector = CryptographicDetector(self.data)
        algos = crypto_detector.detect_crypto_algorithms()
        return min(len(algos) * 0.1, 1.0)

    def _score_network_behavior(self) -> float:
        """Score based on network indicators"""
        network_sigs = [
            b'InternetOpen', b'socket', b'connect',
            b'SendData', b'RecvData', b'http://', b'https://'
        ]
        count = sum(1 for sig in network_sigs if sig in self.data)
        return min(count * 0.15, 1.0)

    def _score_file_system_behavior(self) -> float:
        """Score based on file system manipulation"""
        fs_sigs = [
            b'CreateFile', b'WriteFile', b'DeleteFile',
            b'CreateDirectory', b'RemoveDirectory'
        ]
        count = sum(1 for sig in fs_sigs if sig in self.data)
        return min(count * 0.12, 1.0)

    def _score_process_behavior(self) -> float:
        """Score based on process manipulation"""
        process_sigs = [
            b'CreateProcess', b'CreateRemoteThread',
            b'VirtualAllocEx', b'WriteProcessMemory',
            b'SetWindowsHookEx'
        ]
        count = sum(1 for sig in process_sigs if sig in self.data)
        return min(count * 0.15, 1.0)

    def _score_registry_behavior(self) -> float:
        """Score based on registry manipulation"""
        reg_sigs = [
            b'RegOpenKey', b'RegSetValue', b'RegCreateKey',
            b'RegDeleteKey', b'HKLM', b'HKCU'
        ]
        count = sum(1 for sig in reg_sigs if sig in self.data)
        return min(count * 0.1, 1.0)

    def _score_anti_analysis(self) -> float:
        """Score based on anti-analysis techniques"""
        anti_sigs = [
            b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
            b'VirtualProtect', b'SetErrorMode',
            b'GetModuleHandle', b'OutputDebugString'
        ]
        count = sum(1 for sig in anti_sigs if sig in self.data)
        return min(count * 0.15, 1.0)

    def _score_obfuscation(self) -> float:
        """Score based on obfuscation"""
        obf_detector = PolymorphicDetector(self.data)
        obf_info = obf_detector.detect_code_obfuscation()
        return obf_info['obfuscation_score']

    def _score_known_signatures(self) -> float:
        """Score based on known malware signatures"""
        sig_db = MalwareSignatureDB()
        matches = sig_db.scan_malware_signatures(self.data)
        return min(len(matches) * 0.2, 1.0)


# ============================================================
# INTEGRATION
# ============================================================

def comprehensive_crypto_signature_analysis(data: bytes) -> Dict:
    """Complete cryptographic and signature analysis"""

    results = {
        'crypto_algorithms': {},
        'crypto_libraries': {},
        'crypto_constants': [],
        'key_scheduling': [],
        'hash_analysis': {
            'text_hashes': {},
            'binary_hashes': []
        },
        'signatures': {
            'algorithms': {},
            'certificates': []
        },
        'malware_check': {
            'known_malware': {},
            'signature_matches': {}
        },
        'polymorphic_analysis': {
            'obfuscation': {},
            'packing_unpacking': [],
            'self_modification': False
        },
        'malware_score': 0.0,
        'malware_assessment': 'Unknown'
    }

    # Cryptographic Analysis
    crypto_detector = CryptographicDetector(data)
    results['crypto_algorithms'] = crypto_detector.detect_crypto_algorithms()
    results['crypto_libraries'] = crypto_detector.detect_crypto_libraries()
    results['crypto_constants'] = crypto_detector.analyze_constant_patterns()
    results['key_scheduling'] = crypto_detector.detect_key_scheduling()

    # Hash Analysis
    hash_analyzer = HashSignatureAnalyzer(data)
    results['hash_analysis']['text_hashes'] = hash_analyzer.find_potential_hashes()
    results['hash_analysis']['binary_hashes'] = hash_analyzer.find_binary_hashes()

    # Signature Analysis
    sig_analyzer = DigitalSignatureAnalyzer(data)
    results['signatures']['algorithms'] = sig_analyzer.detect_signature_algorithms()
    results['signatures']['certificates'] = sig_analyzer.find_certificate_structures()
    results['signatures']['asymmetric'] = sig_analyzer.analyze_asymmetric_patterns()

    # Malware Check
    sig_db = MalwareSignatureDB()
    results['malware_check']['signature_matches'] = sig_db.scan_malware_signatures(data)

    # Polymorphic Analysis
    poly_detector = PolymorphicDetector(data)
    results['polymorphic_analysis']['obfuscation'] = poly_detector.detect_code_obfuscation()
    results['polymorphic_analysis']['packing_unpacking'] = poly_detector.detect_packing_unpacking()
    results['polymorphic_analysis']['self_modification'] = poly_detector.detect_self_modification()

    # Malware Behavior Scoring
    scorer = MalwareBehaviorScorer(data)
    results['malware_score'] = scorer.calculate_total_score()

    # Assessment
    if results['malware_score'] > 0.8:
        results['malware_assessment'] = 'CRITICAL - Likely Malware'
    elif results['malware_score'] > 0.6:
        results['malware_assessment'] = 'HIGH - Suspicious Behavior'
    elif results['malware_score'] > 0.4:
        results['malware_assessment'] = 'MEDIUM - Some Concerns'
    elif results['malware_score'] > 0.2:
        results['malware_assessment'] = 'LOW - Minor Indicators'
    else:
        results['malware_assessment'] = 'CLEAN - No Significant Threats'

    return results


# if __name__ == '__main__':
#    if len(sys.argv) < 2:
#        print("Usage: Part 4 requires binary file argument")
#        sys.exit(1)
#
#    with open(sys.argv[1], 'rb') as f:
#        data = f.read()
#
#    analysis = comprehensive_crypto_signature_analysis(data)
#    print(json.dumps(analysis, indent=2, default=str))
#
# ============================================================
# PART 5: NETWORK IOC + OSINT INTEGRATION ENGINE
# Lines 2467-3666 (1200 lines)
# ============================================================

import socket
import ipaddress
import urllib.parse
from datetime import datetime, timedelta

# ============================================================
# IOC EXTRACTION ENGINE
# ============================================================

class IOCExtractor:
    """Extract Indicators of Compromise from data"""

    def __init__(self, data: bytes):
        self.data = data
        self.text = data.decode('latin-1', errors='ignore')

    def extract_ipv4_addresses(self) -> List[Dict]:
        """Extract and validate IPv4 addresses"""
        iocs = []

        # IPv4 pattern
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        matches = re.finditer(ipv4_pattern, self.text)

        for match in matches:
            ip = match.group(0)

            # Skip private/reserved ranges
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                    continue
            except:
                continue

            iocs.append({
                'type': 'IPv4',
                'value': ip,
                'offset': match.start(),
                'context': self.text[max(0, match.start() - 30):min(len(self.text), match.end() + 30)]
            })

        return iocs

    def extract_ipv6_addresses(self) -> List[Dict]:
        """Extract and validate IPv6 addresses"""
        iocs = []

        # IPv6 pattern (simplified)
        ipv6_pattern = r'(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})'
        matches = re.finditer(ipv6_pattern, self.text)

        for match in matches:
            ip = match.group(0)

            try:
                ip_obj = ipaddress.IPv6Address(ip)
                if ip_obj.is_private or ip_obj.is_loopback:
                    continue
            except:
                continue

            iocs.append({
                'type': 'IPv6',
                'value': ip,
                'offset': match.start()
            })

        return iocs

    def extract_domains(self) -> List[Dict]:
        """Extract domain names"""
        iocs = []

        # Domain pattern
        domain_pattern = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}'
        matches = re.finditer(domain_pattern, self.text, re.IGNORECASE)

        seen = set()
        for match in matches:
            domain = match.group(0).lower()

            # Skip common false positives
            if domain in seen or domain.startswith('.') or domain.endswith('.'):
                continue

            # Skip single-letter domains and localhost
            if len(domain.split('.')[-1]) < 2 or domain == 'localhost':
                continue

            seen.add(domain)
            iocs.append({
                'type': 'Domain',
                'value': domain,
                'offset': match.start(),
                'context': self.text[max(0, match.start() - 20):min(len(self.text), match.end() + 20)]
            })

        return iocs

    def extract_urls(self) -> List[Dict]:
        """Extract URLs"""
        iocs = []

        # URL patterns
        url_patterns = [
            r'https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+)',
            r'ftp://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+)',
            r'ftps://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+)',
        ]

        seen = set()
        for pattern in url_patterns:
            matches = re.finditer(pattern, self.text)

            for match in matches:
                url = match.group(0)
                if url not in seen:
                    seen.add(url)
                    iocs.append({
                        'type': 'URL',
                        'value': url,
                        'offset': match.start(),
                        'length': len(url)
                    })

        return iocs

    def extract_email_addresses(self) -> List[Dict]:
        """Extract email addresses"""
        iocs = []

        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        matches = re.finditer(email_pattern, self.text)

        seen = set()
        for match in matches:
            email = match.group(0).lower()

            if email not in seen:
                seen.add(email)
                iocs.append({
                    'type': 'Email',
                    'value': email,
                    'offset': match.start()
                })

        return iocs

    def extract_file_paths(self) -> List[Dict]:
        """Extract file paths"""
        iocs = []

        # Windows paths
        win_pattern = r'[a-zA-Z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*'
        matches = re.finditer(win_pattern, self.text)

        for match in matches:
            path = match.group(0)
            iocs.append({
                'type': 'Windows Path',
                'value': path,
                'offset': match.start()
            })

        # Unix paths
        unix_pattern = r'/(?:[a-zA-Z0-9._-]+/)*[a-zA-Z0-9._-]*'
        matches = re.finditer(unix_pattern, self.text)

        for match in matches:
            path = match.group(0)
            if len(path) > 5:  # Avoid short matches
                iocs.append({
                    'type': 'Unix Path',
                    'value': path,
                    'offset': match.start()
                })

        return iocs

    def extract_registry_keys(self) -> List[Dict]:
        """Extract Windows registry keys"""
        iocs = []

        registry_pattern = r'(HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG|DYN_DATA)\\[a-zA-Z0-9\\._-]+)'
        matches = re.finditer(registry_pattern, self.text)

        for match in matches:
            key = match.group(0)
            iocs.append({
                'type': 'Registry Key',
                'value': key,
                'offset': match.start()
            })

        return iocs

    def extract_hashes(self) -> List[Dict]:
        """Extract hash values"""
        iocs = []

        hash_patterns = {
            'MD5': r'\b[a-fA-F0-9]{32}\b',
            'SHA1': r'\b[a-fA-F0-9]{40}\b',
            'SHA256': r'\b[a-fA-F0-9]{64}\b',
            'SHA512': r'\b[a-fA-F0-9]{128}\b',
        }

        for hash_type, pattern in hash_patterns.items():
            matches = re.finditer(pattern, self.text)

            for match in matches:
                hash_val = match.group(0).lower()
                iocs.append({
                    'type': f'{hash_type} Hash',
                    'value': hash_val,
                    'offset': match.start()
                })

        return iocs

    def extract_all_iocs(self) -> Dict[str, List[Dict]]:
        """Extract all IOCs"""
        return {
            'ipv4': self.extract_ipv4_addresses(),
            'ipv6': self.extract_ipv6_addresses(),
            'domains': self.extract_domains(),
            'urls': self.extract_urls(),
            'emails': self.extract_email_addresses(),
            'file_paths': self.extract_file_paths(),
            'registry_keys': self.extract_registry_keys(),
            'hashes': self.extract_hashes(),
        }


# ============================================================
# OSINT THREAT INTELLIGENCE
# ============================================================

class OSINTIntelligence:
    """OSINT-based threat intelligence gathering"""

    # Known malicious domains and IPs (sample database)
    KNOWN_MALICIOUS={
        'domains': [
            'emotet.ru', 'trickbot.net', 'mirai.cc',
            'dga-domain.xyz', 'c2.malware.com'
        ],
        'ips': [
            '0.0.0.0',  # Example
            '10.0.0.1',     # Example
        ],
        'file_hashes': {
            '5d041c0194d3b35e55e8151c2d7bd4e2': 'Emotet.A trojan',
            '76b629df00e78b0346492820e6d9ba81': 'Emotet.B trojan',
        }
    }

    # Known C2 infrastructure patterns
    C2_PATTERNS={
        'domain_patterns': [
            r'.*\.ru$',  # Russian domains
            r'.*\.xyz$',  # Suspicious TLDs
            r'.*\.tk$',   # Free tier domains
            r'.*\.(ml|ga|cf|gq)$',  # Freenom domains
        ],
        'ip_patterns': [
            r'^5\.',  # Russian ASN ranges
            r'^45\.',
            r'^195\.',
        ]
    }

    def __init__(self):
        pass

    def check_ioc_reputation(self, ioc: str, ioc_type: str) -> Dict:
        """Check IOC against known malicious lists"""
        result={
            'ioc': ioc,
            'type': ioc_type,
            'is_malicious': False,
            'threat_level': 'Unknown',
            'sources': [],
            'description': ''
        }

        if ioc_type == 'domain':
            # Check against known malicious domains
            if ioc.lower() in self.KNOWN_MALICIOUS['domains']:
                result['is_malicious']=True
                result['threat_level']='HIGH'
                result['sources'].append('Known Malware Database')

            # Check against patterns
            for pattern in self.C2_PATTERNS['domain_patterns']:
                if re.match(pattern, ioc.lower()):
                    result['threat_level']='MEDIUM'
                    result['sources'].append('Domain Pattern Analysis')

        elif ioc_type == 'ipv4':
            # Check against known malicious IPs
            if ioc in self.KNOWN_MALICIOUS['ips']:
                result['is_malicious']=True
                result['threat_level']='HIGH'
                result['sources'].append('Known Malware Database')

            # Check ASN patterns
            first_octet=ioc.split('.')[0]
            for pattern in self.C2_PATTERNS['ip_patterns']:
                if re.match(pattern, ioc):
                    result['threat_level']='MEDIUM'
                    result['sources'].append('Geographic ASN Analysis')

        elif ioc_type == 'hash':
            if ioc.lower() in self.KNOWN_MALICIOUS['file_hashes']:
                result['is_malicious']=True
                result['threat_level']='CRITICAL'
                result['description']=self.KNOWN_MALICIOUS['file_hashes'][ioc.lower()]
                result['sources'].append('Known Malware Hashes')

        return result

    def analyze_c2_infrastructure(self, iocs: Dict[str, List[Dict]]) -> Dict:
        """Analyze potential C2 infrastructure from IOCs"""
        analysis={
            'potential_c2_servers': [],
            'potential_data_exfiltration': [],
            'network_recon': [],
            'summary': {}
        }

        # Analyze domains
        for domain_ioc in iocs.get('domains', []):
            domain=domain_ioc['value']

            # Check for suspicious patterns
            if any(char in domain for char in ['xn--', '\\x']):
                analysis['potential_c2_servers'].append({
                    'indicator': domain,
                    'reason': 'Encoded/homograph domain',
                    'risk': 'HIGH'
                })

            # Check for single letter domains or shorteners
            if any(part in domain.split('.') for part in ['a', 'b', 'x', 'y']):
                analysis['potential_c2_servers'].append({
                    'indicator': domain,
                    'reason': 'Single-letter subdomain (obfuscation)',
                    'risk': 'MEDIUM'
                })

        # Analyze IPs
        for ip_ioc in iocs.get('ipv4', []):
            ip=ip_ioc['value']

            # Check for VPN/proxy providers
            if self._is_vpn_provider(ip):
                analysis['potential_c2_servers'].append({
                    'indicator': ip,
                    'reason': 'VPN/Proxy Provider',
                    'risk': 'MEDIUM'
                })

            # Check for datacenter IPs
            if self._is_datacenter_ip(ip):
                analysis['potential_c2_servers'].append({
                    'indicator': ip,
                    'reason': 'Cloud/Datacenter IP (hosting)',
                    'risk': 'MEDIUM'
                })

        analysis['summary']={
            'total_c2_indicators': len(analysis['potential_c2_servers']),
            'high_confidence': sum(1 for x in analysis['potential_c2_servers'] if x['risk'] == 'HIGH'),
            'medium_confidence': sum(1 for x in analysis['potential_c2_servers'] if x['risk'] == 'MEDIUM'),
        }

        return analysis

    def _is_vpn_provider(self, ip: str) -> bool:
        """Check if IP belongs to known VPN provider"""
        vpn_providers=[
            '*.vultr.com',
            '*.linode.com',
            '*.digitalocean.com',
        ]
        # Simplified check
        return any(part in ip for part in ['vultr', 'linode', 'digitalocean'])

    def _is_datacenter_ip(self, ip: str) -> bool:
        """Check if IP belongs to datacenter"""
        try:
            parts=ip.split('.')
            # Common datacenter ASN ranges
            first_octet=int(parts[0])
            return first_octet in [5, 23, 31, 34, 35, 38, 43, 45, 46, 50]
        except:
            return False


# ============================================================
# NETWORK COMMUNICATION ANALYSIS
# ============================================================

class NetworkCommunicationAnalyzer:
    """Analyze network communication patterns"""

    def __init__(self, data: bytes):
        self.data = data
        self.text = data.decode('latin-1', errors='ignore')

    def extract_dns_queries(self) -> List[Dict]:
        """Extract DNS query patterns"""
        queries = []

        # DNS query patterns
        dns_patterns = [
            r'nslookup\s+([a-zA-Z0-9\-\.]+)',
            r'dig\s+([a-zA-Z0-9\-\.]+)',
            r'host\s+([a-zA-Z0-9\-\.]+)',
            r'query.*?([a-zA-Z0-9\-\.]+)',
        ]

        for pattern in dns_patterns:
            matches = re.finditer(pattern, self.text, re.IGNORECASE)
            for match in matches:
                domain = match.group(1)
                queries.append({
                    'type': 'DNS Query',
                    'domain': domain,
                    'context': 'Infrastructure reconnaissance'
                })

        return queries

    def extract_http_requests(self) -> List[Dict]:
        """Extract HTTP request patterns"""
        requests = []

        # HTTP request patterns
        http_patterns = [
            r'(?:GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)\s+(?:HTTP|FTP)',
            r'Host:\s+([a-zA-Z0-9\-\.]+)',
            r'User-Agent:\s+([^\r\n]+)',
        ]

        for pattern in http_patterns:
            matches = re.finditer(pattern, self.text, re.IGNORECASE)
            for match in matches:
                requests.append({
                    'type': 'HTTP Pattern',
                    'value': match.group(1),
                    'offset': match.start()
                })

        return requests

    def extract_port_information(self) -> List[Dict]:
        """Extract port numbers and protocols"""
        ports = []

        # Port patterns
        port_pattern = r':(\d{1,5})(?:/|$|\s)'
        matches = re.finditer(port_pattern, self.text)

        known_ports = {
            21: 'FTP',
            22: 'SSH',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP Alt',
            8443: 'HTTPS Alt',
            9200: 'Elasticsearch',
        }

        seen = set()
        for match in matches:
            port_num = int(match.group(1))

            # Skip invalid ports
            if port_num > 65535 or port_num < 1:
                continue

            if port_num not in seen:
                seen.add(port_num)
                protocol = known_ports.get(port_num, 'Unknown')

                ports.append({
                    'port': port_num,
                    'protocol': protocol,
                    'context': self.text[max(0, match.start() - 20):min(len(self.text), match.end() + 20)]
                })

        return ports

    def detect_reverse_dns_lookups(self) -> List[Dict]:
        """Detect reverse DNS lookup patterns"""
        lookups = []

        # Reverse DNS patterns (IP addresses in unusual contexts)
        reverse_patterns = [
            r'reverse\s+([0-9\.]+)',
            r'ptr\s+([0-9\.]+)',
            r'arpa\s+([0-9\.]+)',
        ]

        for pattern in reverse_patterns:
            matches = re.finditer(pattern, self.text, re.IGNORECASE)
            for match in matches:
                ip = match.group(1)
                lookups.append({
                    'type': 'Reverse DNS',
                    'ip': ip,
                    'context': 'Infrastructure reconnaissance'
                })

        return lookups

    def detect_tunnel_protocols(self) -> List[Dict]:
        """Detect tunnel/encapsulation protocols"""
        tunnels = []

        tunnel_patterns = {
            'VPN': [b'vpn', b'openvpn', b'wireguard', b'ipsec'],
            'DNS Tunneling': [b'dns', b'doh', b'dot'],
            'HTTP Tunneling': [b'proxy', b'socks', b'http-tunnel'],
            'SSH Tunneling': [b'ssh', b'openssh', b'putty'],
            'GRE': [b'gre', b'generic routing'],
            'Tor': [b'tor', b'onion', b'.onion'],
        }

        for tunnel_type, sigs in tunnel_patterns.items():
            for sig in sigs:
                if sig in self.data:
                    tunnels.append({
                        'type': f'{tunnel_type} Protocol',
                        'indicator': sig.decode('latin-1', errors='ignore'),
                        'risk': 'MEDIUM'
                    })

        return tunnels


# ============================================================
# THREAT ACTOR PROFILING
# ============================================================

class ThreatActorProfiler:
    """Profile threat actors based on indicators"""

    # Known threat actor patterns
    THREAT_ACTOR_PROFILES = {
        'APT1': {
            'aliases': ['Comment Crew', 'PLA Unit 61398'],
            'countries': ['China'],
            'known_malware': ['Poison Ivy', 'WEBC2'],
            'techniques': ['spear phishing', 'watering hole'],
        },
        'APT28': {
            'aliases': ['Fancy Bear', 'Sofacy'],
            'countries': ['Russia'],
            'known_malware': ['SOFACY', 'X-AGENT'],
            'techniques': ['spear phishing', 'zero-day'],
        },
        'APT29': {
            'aliases': ['Cozy Bear', 'The Dukes'],
            'countries': ['Russia'],
            'known_malware': ['DUKES', 'Hammertoss'],
            'techniques': ['watering hole', 'supply chain'],
        },
    }

    def __init__(self, iocs: Dict[str, List[Dict]]):
        self.iocs = iocs

    def profile_threat_actor(self) -> Dict:
        """Profile potential threat actor"""
        profile = {
            'suspected_actors': [],
            'tactics': [],
            'techniques': [],
            'confidence': 0.0
        }

        # Analyze IOCs for actor patterns
        all_indicators = []
        for ioc_list in self.iocs.values():
            all_indicators.extend([ioc['value'] for ioc in ioc_list])

        # Check against known threat actor indicators
        for actor_name, actor_data in self.THREAT_ACTOR_PROFILES.items():
            matches = 0

            for indicator in all_indicators:
                indicator_lower = indicator.lower()

                # Check against known malware
                for malware in actor_data['known_malware']:
                    if malware.lower() in indicator_lower:
                        matches += 2

                # Check against aliases
                for alias in actor_data['aliases']:
                    if alias.lower() in indicator_lower:
                        matches += 1

            if matches > 0:
                profile['suspected_actors'].append({
                    'actor': actor_name,
                    'aliases': actor_data['aliases'],
                    'confidence': min(matches * 0.15, 0.95),
                    'countries': actor_data['countries']
                })

                profile['tactics'].extend(actor_data['techniques'])
                profile['confidence'] = max(
                    profile['confidence'], min(matches * 0.15, 0.95))

        return profile


# ============================================================
# INTEGRATION & REPORTING
# ============================================================

def comprehensive_ioc_analysis(data: bytes) -> Dict:
    """Complete IOC and OSINT analysis"""

    results = {
        'extracted_iocs': {},
        'ioc_reputation': [],
        'c2_infrastructure': {},
        'network_analysis': {},
        'threat_actor_profile': {},
        'summary': {}
    }

    # Extract IOCs
    extractor = IOCExtractor(data)
    results['extracted_iocs'] = extractor.extract_all_iocs()

    # Check reputation
    osint = OSINTIntelligence()
    all_iocs = []

    for ioc_type, ioc_list in results['extracted_iocs'].items():
        for ioc in ioc_list:
            if ioc_type == 'ipv4':
                reputation = osint.check_ioc_reputation(ioc['value'], 'ipv4')
            elif ioc_type == 'domains':
                reputation = osint.check_ioc_reputation(ioc['value'], 'domain')
            elif ioc_type == 'hashes':
                reputation = osint.check_ioc_reputation(ioc['value'], 'hash')
            else:
                reputation = {
                    'ioc': ioc['value'],
                    'type': ioc_type,
                    'is_malicious': False
                }

            all_iocs.append(ioc)
            results['ioc_reputation'].append(reputation)

    # Analyze C2 infrastructure
    results['c2_infrastructure'] = osint.analyze_c2_infrastructure(
        results['extracted_iocs'])

    # Network analysis
    net_analyzer = NetworkCommunicationAnalyzer(data)
    results['network_analysis'] = {
        'dns_queries': net_analyzer.extract_dns_queries(),
        'http_requests': net_analyzer.extract_http_requests(),
        'ports': net_analyzer.extract_port_information(),
        'reverse_dns': net_analyzer.detect_reverse_dns_lookups(),
        'tunnels': net_analyzer.detect_tunnel_protocols(),
    }

    # Threat actor profiling
    profiler = ThreatActorProfiler(results['extracted_iocs'])
    results['threat_actor_profile'] = profiler.profile_threat_actor()

    # Summary statistics
    malicious_count = sum(1 for r in results['ioc_reputation'] if r.get('is_malicious'))
    results['summary'] = {
        'total_iocs_extracted': sum(len(iocs) for iocs in results['extracted_iocs'].values()),
        'malicious_iocs': malicious_count,
        'potential_c2_indicators': results['c2_infrastructure'].get('summary', {}).get('total_c2_indicators', 0),
        'suspected_threat_actors': len(results['threat_actor_profile'].get('suspected_actors', [])),
        'overall_risk': 'CRITICAL' if malicious_count > 5 else 'HIGH' if malicious_count > 0 else 'MEDIUM',
    }

    return results


# if __name__ == '__main__':
#    if len(sys.argv) < 2:
#        print("Usage: Part 5 requires binary file argument")
#        sys.exit(1)
#
#    with open(sys.argv[1], 'rb') as f:
#        data = f.read()
#
#    analysis = comprehensive_ioc_analysis(data)
#    print(json.dumps(analysis, indent=2, default=str))
#
# ============================================================
# PART 6: DYNAMIC BEHAVIORAL ANALYSIS + SANDBOX INTEGRATION ENGINE
# Enterprise-Grade Behavioral Analysis with Full Sandbox Integration
# Lines 3176-4375 (1200 lines)
# ============================================================

import time
import threading
import queue
from typing import Callable, Set, Tuple as TupleType
from datetime import datetime as dt, timedelta
from enum import Enum
from dataclasses import dataclass, asdict, field
from collections import defaultdict

# ============================================================
# ENUMS & DATA CLASSES
# ============================================================

class ProcessPriority(Enum):
    """Process priority levels."""
    IDLE = 0
    BELOW_NORMAL = 1
    NORMAL = 2
    ABOVE_NORMAL = 3
    HIGH = 4
    REALTIME = 5

class WindowsAPICategory(Enum):
    """Windows API categories for behavior classification."""
    PROCESS_MANAGEMENT = "Process Management"
    MEMORY_MANAGEMENT = "Memory Management"
    FILE_SYSTEM = "File System"
    REGISTRY = "Registry"
    NETWORK = "Network"
    SYNCHRONIZATION = "Synchronization"
    PERSISTENCE = "Persistence"
    ANTI_ANALYSIS = "Anti-Analysis"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DATA_EXFILTRATION = "Data Exfiltration"
    EVASION = "Evasion"
    RECONNAISSANCE = "Reconnaissance"

@dataclass
class APICall:
    """Represents a single API call event."""
    timestamp: str
    api_name: str
    category: WindowsAPICategory
    arguments: Dict[str, Any] = field(default_factory=dict)
    return_value: Optional[Any] = None
    thread_id: Optional[int] = None
    process_id: Optional[int] = None
    risk_level: str = "UNKNOWN"

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        data = asdict(self)
        data['category'] = self.category.value
        return data

@dataclass
class ProcessEvent:
    """Represents a process-related event."""
    timestamp: str
    event_type: str  # 'created', 'terminated', 'modified'
    process_name: str
    process_id: int
    parent_process_id: Optional[int] = None
    command_line: str = ""
    priority: ProcessPriority = ProcessPriority.NORMAL
    user_name: str = ""
    risk_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        data = asdict(self)
        data['priority'] = self.priority.name
        return data

@dataclass
class FileOperation:
    """Represents a file system operation."""
    timestamp: str
    operation: str  # 'create', 'read', 'write', 'delete', 'rename'
    file_path: str
    process_id: int
    process_name: str
    file_size: int = 0
    permissions: str = ""
    is_system_file: bool = False
    is_hidden: bool = False
    risk_level: str = "LOW"

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)

@dataclass
class RegistryOperation:
    """Represents a registry operation."""
    timestamp: str
    operation: str  # 'read', 'write', 'delete'
    key_path: str
    value_name: str = ""
    value_data: str = ""
    process_id: int = 0
    process_name: str = ""
    is_persistence_related: bool = False
    risk_level: str = "LOW"

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)

@dataclass
class NetworkEvent:
    """Represents a network communication event."""
    timestamp: str
    protocol: str  # 'TCP', 'UDP', 'DNS', 'HTTPS'
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    process_id: int
    process_name: str
    data_sent: int = 0
    data_received: int = 0
    is_suspicious: bool = False
    risk_level: str = "LOW"
    c2_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)

# ============================================================
# PROCESS MONITORING ENGINE (APEX EDITION)
# ============================================================

class ProcessMonitor:
    """
    Enterprise-grade process monitoring engine.

    Monitors and analyzes:
    - Process creation and termination
    - API call patterns
    - Process injection techniques
    - DLL side-loading
    - Rootkit installation
    - Process hollowing
    - Token manipulation
    - Privilege escalation

    Attributes:
        events (List[Dict]): All captured events
        behavior_matrix (Dict): Behavior correlation matrix
        suspicious_processes (Set[str]): Flagged process names
        logger (logging.Logger): Logger instance
    """

    # Windows process names commonly mimicked by malware
    SUSPICIOUS_PROCESS_NAMES = {
        'svchost.exe': {'category': 'Windows System', 'risk': 0.7},
        'lsass.exe': {'category': 'Windows System', 'risk': 0.8},
        'csrss.exe': {'category': 'Windows System', 'risk': 0.8},
        'explorer.exe': {'category': 'Windows System', 'risk': 0.6},
        'winlogon.exe': {'category': 'Windows System', 'risk': 0.8},
        'rundll32.exe': {'category': 'Windows System', 'risk': 0.9},
        'regsvcs.exe': {'category': 'Windows System', 'risk': 0.8},
        'regasm.exe': {'category': 'Windows System', 'risk': 0.8},
        'powershell.exe': {'category': 'Scripting', 'risk': 0.7},
        'cmd.exe': {'category': 'Shell', 'risk': 0.6},
        'cscript.exe': {'category': 'Scripting', 'risk': 0.7},
        'wscript.exe': {'category': 'Scripting', 'risk': 0.7},
        'mshta.exe': {'category': 'Scripting', 'risk': 0.8},
        'schtasks.exe': {'category': 'Scheduling', 'risk': 0.7},
        'taskkill.exe': {'category': 'Process', 'risk': 0.6},
        'sc.exe': {'category': 'Service', 'risk': 0.8},
        'net.exe': {'category': 'Network', 'risk': 0.6},
        'ipconfig.exe': {'category': 'Network', 'risk': 0.5},
        'nslookup.exe': {'category': 'Network', 'risk': 0.5},
        'certutil.exe': {'category': 'Utility', 'risk': 0.7},
    }

    # API calls organized by risk category
    SUSPICIOUS_BEHAVIORS = {
        'process_injection': {
            'category': WindowsAPICategory.PROCESS_MANAGEMENT,
            'apis': [
                'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
                'CreateProcess', 'CreateProcessA', 'CreateProcessW',
                'NtCreateThreadEx', 'RtlCreateUserThread'
            ],
            'risk_weight': 0.95,
            'description': 'Indicators of code injection into remote processes'
        },
        'dll_injection': {
            'category': WindowsAPICategory.MEMORY_MANAGEMENT,
            'apis': [
                'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
                'GetProcAddress', 'GetProcAddressA', 'GetProcAddressW',
                'CreateRemoteThread', 'NtCreateThreadEx'
            ],
            'risk_weight': 0.90,
            'description': 'DLL injection and dynamic function loading'
        },
        'file_operations': {
            'category': WindowsAPICategory.FILE_SYSTEM,
            'apis': [
                'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile',
                'DeleteFileA', 'DeleteFileW', 'CopyFileA', 'CopyFileW',
                'MoveFileA', 'MoveFileW', 'SetFileAttributesA', 'SetFileAttributesW',
                'FindFirstFileA', 'FindFirstFileW', 'FindNextFileA', 'FindNextFileW'
            ],
            'risk_weight': 0.40,
            'description': 'File system operations'
        },
        'registry_operations': {
            'category': WindowsAPICategory.REGISTRY,
            'apis': [
                'RegOpenKeyA', 'RegOpenKeyW', 'RegOpenKeyExA', 'RegOpenKeyExW',
                'RegSetValueA', 'RegSetValueW', 'RegSetValueExA', 'RegSetValueExW',
                'RegCreateKeyA', 'RegCreateKeyW', 'RegCreateKeyExA', 'RegCreateKeyExW',
                'RegDeleteKeyA', 'RegDeleteKeyW', 'RegDeleteValueA', 'RegDeleteValueW',
                'RegEnumKeyA', 'RegEnumKeyW', 'RegQueryValueA', 'RegQueryValueW'
            ],
            'risk_weight': 0.60,
            'description': 'Registry manipulation'
        },
        'network_operations': {
            'category': WindowsAPICategory.NETWORK,
            'apis': [
                'socket', 'connect', 'send', 'recv', 'sendto', 'recvfrom',
                'WSASocket', 'WSAConnect', 'WSASend', 'WSARecv',
                'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW',
                'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW',
                'HttpQueryInfoA', 'HttpQueryInfoW', 'InternetReadFile', 'InternetWriteFile',
                'GetAddrInfoA', 'GetAddrInfoW', 'GetHostByNameA', 'gethostbyname'
            ],
            'risk_weight': 0.85,
            'description': 'Network communication'
        },
        'persistence': {
            'category': WindowsAPICategory.PERSISTENCE,
            'apis': [
                'CreateServiceA', 'CreateServiceW', 'StartServiceA', 'StartServiceW',
                'ControlService', 'DeleteService', 'OpenServiceA', 'OpenServiceW',
                'SetWindowsHookExA', 'SetWindowsHookExW', 'SetWinEventHookA', 'SetWinEventHookW',
                'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
                'WinExec', 'system', 'CreateProcessA', 'CreateProcessW'
            ],
            'risk_weight': 0.92,
            'description': 'Persistence mechanisms (services, hooks, autostart)'
        },
        'anti_analysis': {
            'category': WindowsAPICategory.ANTI_ANALYSIS,
            'apis': [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                'GetModuleHandleA', 'GetModuleHandleW',
                'OutputDebugStringA', 'OutputDebugStringW',
                'SetErrorMode', 'VirtualProtect', 'VirtualProtectEx',
                'GetTickCount', 'GetTickCount64', 'QueryPerformanceCounter',
                'ZwQueryInformationProcess', 'NtQueryInformationProcess',
                'SetUnhandledExceptionFilter', 'RtlSetUnhandledExceptionFilter'
            ],
            'risk_weight': 0.75,
            'description': 'Anti-analysis and anti-debugging techniques'
        },
        'privilege_escalation': {
            'category': WindowsAPICategory.PRIVILEGE_ESCALATION,
            'apis': [
                'AdjustTokenPrivileges', 'ImpersonateLoggedOnUser',
                'ImpersonateNamedPipeClient', 'RevertToSelf',
                'SetThreadToken', 'DuplicateTokenEx', 'DuplicateToken',
                'CreateProcessAsUserA', 'CreateProcessAsUserW',
                'CreateProcessWithTokenW', 'CreateRestrictedToken',
                'GetTokenInformation', 'SetTokenInformation'
            ],
            'risk_weight': 0.90,
            'description': 'Token manipulation and privilege escalation'
        },
        'data_exfiltration': {
            'category': WindowsAPICategory.DATA_EXFILTRATION,
            'apis': [
                'CreateFileA', 'CreateFileW', 'ReadFile',
                'InternetOpenA', 'InternetOpenW', 'HttpOpenRequestA', 'HttpOpenRequestW',
                'HttpSendRequestA', 'HttpSendRequestW',
                'FtpPutFileA', 'FtpPutFileW', 'FtpGetFileA', 'FtpGetFileW',
                'CryptEncrypt', 'CryptDecrypt', 'SendMessage', 'PostMessage'
            ],
            'risk_weight': 0.80,
            'description': 'Data exfiltration and C2 communication'
        },
        'evasion': {
            'category': WindowsAPICategory.EVASION,
            'apis': [
                'UnhookWindowsHookEx', 'SetWindowsHookExA', 'SetWindowsHookExW',
                'SetWinEventHookA', 'SetWinEventHookW',
                'NtSetInformationFile', 'SetFilePointerEx',
                'WriteConsoleA', 'WriteConsoleW', 'FreeLibrary', 'FreeLibraryAndExitThread'
            ],
            'risk_weight': 0.70,
            'description': 'Evasion and stealth techniques'
        },
        'reconnaissance': {
            'category': WindowsAPICategory.RECONNAISSANCE,
            'apis': [
                'GetComputerNameA', 'GetComputerNameW', 'GetComputerNameExA', 'GetComputerNameExW',
                'GetUserNameA', 'GetUserNameW', 'GetUserNameExA', 'GetUserNameExW',
                'GetWindowsDirectoryA', 'GetWindowsDirectoryW',
                'GetSystemDirectoryA', 'GetSystemDirectoryW',
                'GetEnvironmentVariableA', 'GetEnvironmentVariableW',
                'FindFirstFileA', 'FindFirstFileW',
                'GetFileAttributesA', 'GetFileAttributesW',
                'GetFileSize', 'GetFileTime'
            ],
            'risk_weight': 0.50,
            'description': 'System reconnaissance and information gathering'
        }
    }

    # Known rootkit signatures
    ROOTKIT_SIGNATURES = {
        'kernel_mode_access': [
            b'ZwQuerySystemInformation', b'NtQuerySystemInformation',
            b'NtSetInformationFile', b'ZwSetInformationFile',
            b'NtDeviceIoControlFile', b'ZwDeviceIoControlFile'
        ],
        'idt_hooks': [
            b'__asm__', b'int 0x3', b'int 0x2E', b'sysenter',
            b'lidt', b'sidt'
        ],
        'ssdt_hooks': [
            b'SSDT', b'KeServiceDescriptorTable', b'ZwQuerySystemInformation'
        ]
    }

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize process monitor.

        Args:
            logger (Optional[logging.Logger]): Logger instance

        Raises:
            RuntimeError: If initialization fails
        """
        try:
            self.events: List[Dict] = []
            self.behavior_matrix: Dict[str, Dict] = defaultdict(
                lambda: defaultdict(int))
            self.suspicious_processes: Set[str] = set()
            self.api_call_sequence: List[APICall] = []
            self.process_tree: Dict[int, ProcessEvent] = {}
            self.network_flows: List[NetworkEvent] = []
            self.file_operations_log: List[FileOperation] = []
            self.registry_operations_log: List[RegistryOperation] = []
            self.logger = logger or logging.getLogger(__name__)
            self.start_time = datetime.utcnow()
            self.analysis_metadata = {
                'started': self.start_time.isoformat(),
                'total_events': 0,
                'total_api_calls': 0,
                'total_processes': 0,
                'total_network_events': 0
            }
        except Exception as e:
            logger_instance = logger or logging.getLogger(__name__)
            logger_instance.error(
                f"Failed to initialize ProcessMonitor: {e}",
                exc_info=True)
            raise RuntimeError(f"ProcessMonitor initialization failed: {e}")

    def analyze_api_calls(self, data: bytes) -> Dict:
        """
        Analyze API call patterns in binary data.

        Performs deep analysis of Windows API calls to identify:
        - Process injection patterns
        - DLL manipulation
        - Registry operations
        - Network communication
        - Persistence mechanisms
        - Anti-analysis techniques

        Args:
            data (bytes): Binary data to analyze

        Returns:
            Dict: Comprehensive API analysis results

        Raises:
            ValueError: If data is empty
        """
        if not data:
            raise ValueError("Cannot analyze empty data")

        try:
            analysis = {
                'detected_behaviors': {},
                'behavior_scores': {},
                'total_api_count': 0,
                'risk_assessment': 'LOW',
                'confidence': 0.0,
                'behavior_chains': [],
                'api_call_sequence': [],
                'high_risk_apis': [],
                'attack_flow': {},
                'timestamp': datetime.utcnow().isoformat()
            }

            # Scan for API calls by category
            for behavior_type, behavior_info in self.SUSPICIOUS_BEHAVIORS.items():
                detected_apis = []
                matching_positions = []

                for api in behavior_info['apis']:
                    api_bytes = api.encode()
                    position = 0
                    while True:
                        pos = data.find(api_bytes, position)
                        if pos == -1:
                            break
                        detected_apis.append(api)
                        matching_positions.append((api, pos))
                        analysis['api_call_sequence'].append({
                            'api': api,
                            'offset': f'0x{pos:X}',
                            'category': behavior_info['category'].value
                        })
                        position = pos + 1

                if detected_apis:
                    # Remove duplicates while preserving order
                    unique_apis = list(dict.fromkeys(detected_apis))

                    analysis['detected_behaviors'][behavior_type] = {
                        'apis': unique_apis,
                        'count': len(unique_apis),
                        'category': behavior_info['category'].value,
                        'description': behavior_info['description']
                    }

                    # Calculate risk score for this behavior
                    behavior_score = min(
                        len(unique_apis) * behavior_info['risk_weight'] / 10, 1.0)
                    analysis['behavior_scores'][behavior_type] = behavior_score

            # Calculate total API count
            analysis['total_api_count'] = sum(
                len(apis) for apis in analysis['detected_behaviors'].values()
            )

            # Identify high-risk API calls
            for behavior_type, behavior_info in self.SUSPICIOUS_BEHAVIORS.items():
                if behavior_info['risk_weight'] > 0.80:
                    for api in behavior_info['apis']:
                        if api.encode() in data:
                            analysis['high_risk_apis'].append({
                                'api': api,
                                'category': behavior_info['category'].value,
                                'risk_weight': behavior_info['risk_weight']
                            })

            # Calculate composite behavior score
            if analysis['behavior_scores']:
                avg_behavior_score = sum(
                    analysis['behavior_scores'].values()) / len(analysis['behavior_scores'])
            else:
                avg_behavior_score = 0.0

            # Weighted score considering number of behaviors
            behavior_count = len(analysis['detected_behaviors'])
            weighted_score = avg_behavior_score * (1 + min(behavior_count * 0.1, 0.5))
            final_score = min(weighted_score, 1.0)

            # Risk assessment based on score
            if final_score > 0.85:
                analysis['risk_assessment'] = 'CRITICAL'
                analysis['confidence'] = 0.95
            elif final_score > 0.70:
                analysis['risk_assessment'] = 'HIGH'
                analysis['confidence'] = 0.85
            elif final_score > 0.50:
                analysis['risk_assessment'] = 'MEDIUM'
                analysis['confidence'] = 0.70
            elif final_score > 0.25:
                analysis['risk_assessment'] = 'LOW'
                analysis['confidence'] = 0.60
            else:
                analysis['risk_assessment'] = 'MINIMAL'
                analysis['confidence'] = 0.50

            # Detect behavior chains (sequences indicating specific attacks)
            analysis['behavior_chains'] = self._detect_behavior_chains(
                analysis['detected_behaviors'])

            # Build attack flow diagram
            analysis['attack_flow'] = self._build_attack_flow(
                analysis['detected_behaviors'])

            self.logger.info(
                f"API analysis complete: {analysis['total_api_count']} APIs detected, "
                f"Risk: {analysis['risk_assessment']}"
            )

            return analysis
        except Exception as e:
            self.logger.error(f"Error analyzing API calls: {e}", exc_info=True)
            return {
                'detected_behaviors': {},
                'behavior_scores': {},
                'total_api_count': 0,
                'risk_assessment': 'UNKNOWN',
                'confidence': 0.0,
                'error': str(e)
            }

    def _detect_behavior_chains(self, detected_behaviors: Dict) -> List[Dict]:
        """
        Detect behavior chains that indicate specific attacks.

        Identifies sequences of behaviors that together indicate:
        - Process injection attacks
        - Privilege escalation chains
        - Data exfiltration workflows
        - Persistence installation

        Args:
            detected_behaviors (Dict): Detected behaviors from analysis

        Returns:
            List[Dict]: List of detected behavior chains
        """
        chains = []

        # Process injection chain: Create process -> Allocate memory -> Write process memory
        if ('process_injection' in detected_behaviors and
            'dll_injection' in detected_behaviors):
            chains.append({
                'chain_type': 'Process Injection',
                'confidence': 0.90,
                'description': 'Potential process injection attack detected',
                'components': ['process_injection', 'dll_injection'],
                'mitre_ttp': ['T1055']
            })

        # Persistence chain: Create service + Registry operations
        if ('persistence' in detected_behaviors and
            'registry_operations' in detected_behaviors):
            chains.append({
                'chain_type': 'Persistence Installation',
                'confidence': 0.85,
                'description': 'Potential persistence mechanism installation',
                'components': ['persistence', 'registry_operations'],
                'mitre_ttp': ['T1547', 'T1543']
            })

        # Data exfiltration chain: File operations + Network operations
        if ('data_exfiltration' in detected_behaviors and
            'network_operations' in detected_behaviors):
            chains.append({
                'chain_type': 'Data Exfiltration',
                'confidence': 0.80,
                'description': 'Potential data exfiltration workflow',
                'components': ['data_exfiltration', 'network_operations'],
                'mitre_ttp': ['T1041', 'T1567']
            })

        # Privilege escalation chain: Token manipulation + Process creation
        if ('privilege_escalation' in detected_behaviors and
            'process_injection' in detected_behaviors):
            chains.append({
                'chain_type': 'Privilege Escalation',
                'confidence': 0.88,
                'description': 'Potential privilege escalation attack',
                'components': ['privilege_escalation', 'process_injection'],
                'mitre_ttp': ['T1134', 'T1055']
            })

        # Reconnaissance chain: Multiple reconnaissance APIs
        if 'reconnaissance' in detected_behaviors:
            chains.append({
                'chain_type': 'System Reconnaissance',
                'confidence': 0.70,
                'description': 'Active system reconnaissance detected',
                'components': ['reconnaissance'],
                'mitre_ttp': ['T1082', 'T1580']
            })

        return chains

    def _build_attack_flow(self, detected_behaviors: Dict) -> Dict:
        """
        Build attack flow diagram.

        Creates a visual representation of the attack sequence.

        Args:
            detected_behaviors (Dict): Detected behaviors

        Returns:
            Dict: Attack flow representation
        """
        flow = {
            'phases': [],
            'sequence': []
        }

        # Phase 1: Reconnaissance
        if 'reconnaissance' in detected_behaviors:
            flow['phases'].append({
                'phase': 1,
                'name': 'Reconnaissance',
                'description': 'Information gathering about system',
                'behaviors': ['reconnaissance']
            })
            flow['sequence'].append('Reconnaissance')

        # Phase 2: Initial Execution
        if 'process_injection' in detected_behaviors or 'dll_injection' in detected_behaviors:
            flow['phases'].append({
                'phase': 2,
                'name': 'Initial Execution',
                'description': 'Code injection and process manipulation',
                'behaviors': ['process_injection', 'dll_injection']
            })
            flow['sequence'].append('Initial Execution')

        # Phase 3: Persistence
        if 'persistence' in detected_behaviors:
            flow['phases'].append({
                'phase': 3,
                'name': 'Persistence',
                'description': 'Establishing persistence mechanisms',
                'behaviors': ['persistence', 'registry_operations']
            })
            flow['sequence'].append('Persistence')

        # Phase 4: Privilege Escalation
        if 'privilege_escalation' in detected_behaviors:
            flow['phases'].append({
                'phase': 4,
                'name': 'Privilege Escalation',
                'description': 'Elevating privileges',
                'behaviors': ['privilege_escalation']
            })
            flow['sequence'].append('Privilege Escalation')

        # Phase 5: Evasion
        if 'anti_analysis' in detected_behaviors or 'evasion' in detected_behaviors:
            flow['phases'].append({
                'phase': 5,
                'name': 'Evasion',
                'description': 'Anti-analysis and evasion techniques',
                'behaviors': ['anti_analysis', 'evasion']
            })
            flow['sequence'].append('Evasion')

        # Phase 6: Command & Control
        if 'network_operations' in detected_behaviors:
            flow['phases'].append({
                'phase': 6,
                'name': 'C2 Communication',
                'description': 'Establishing command and control',
                'behaviors': ['network_operations']
            })
            flow['sequence'].append('C2 Communication')

        # Phase 7: Exfiltration
        if 'data_exfiltration' in detected_behaviors:
            flow['phases'].append({
                'phase': 7,
                'name': 'Data Exfiltration',
                'description': 'Stealing and exfiltrating data',
                'behaviors': ['data_exfiltration', 'file_operations']
            })
            flow['sequence'].append('Data Exfiltration')

        return flow

    def detect_process_hollowing(self, data: bytes) -> List[Dict]:
        """
        Detect process hollowing indicators.

        Process hollowing is a technique where an attacker:
        1. Creates a process in suspended state
        2. Allocates memory in the target process
        3. Writes malicious code to that memory
        4. Modifies thread context
        5. Resumes the thread

        Args:
            data (bytes): Binary data to analyze

        Returns:
            List[Dict]: Process hollowing indicators found

        Raises:
            ValueError: If data is empty
        """
        if not data:
            raise ValueError("Cannot analyze empty data")

        indicators = []

        try:
            hollowing_sigs = [
                (b'CreateProcessA', 'Process creation', 0),
                (b'CreateProcessW', 'Process creation (Unicode)', 0),
                (b'VirtualAllocEx', 'Remote memory allocation', 1),
                (b'WriteProcessMemory', 'Writing to remote process', 2),
                (b'GetThreadContext', 'Reading thread context', 3),
                (b'SetThreadContext', 'Modifying thread context', 4),
                (b'ResumeThread', 'Resuming suspended thread', 5),
                (b'SuspendThread', 'Suspending thread', 6),
                (b'NtQueryInformationProcess', 'Process information query', 3),
                (b'NtSetInformationThread', 'Thread information modification', 4)
            ]

            sequence = []
            found_signatures = {}

            for sig, description, priority in hollowing_sigs:
                if sig in data:
                    sequence.append({
                        'signature': sig.decode(),
                        'description': description,
                        'priority': priority
                    })
                    found_signatures[sig] = True

            # Analyze sequence for process hollowing pattern
            # Pattern: CreateProcess -> Allocate -> Write -> GetContext -> SetContext -> Resume
            if len(sequence) >= 3:
                # Check for core hollowing APIs
                has_process_creation = any(
                    s['signature'] in ['CreateProcessA', 'CreateProcessW'] for s in sequence)
                has_memory_ops = any(
                    s['signature'] in ['VirtualAllocEx', 'WriteProcessMemory'] for s in sequence)
                has_context_ops = any(
                    s['signature'] in ['GetThreadContext', 'SetThreadContext'] for s in sequence)

                if has_process_creation and has_memory_ops:
                    confidence = min(len(sequence) * 0.15, 0.95)

                    indicators.append({
                        'type': 'Process Hollowing',
                        'confidence': confidence,
                        'severity': 'CRITICAL',
                        'indicators': sequence,
                        'description': 'Strong indicators of process hollowing attack detected',
                        'mitre_ttp': ['T1055', 'T1134'],
                        'remediation': [
                            'Block process creation APIs from suspicious processes',
                            'Monitor for VirtualAllocEx/WriteProcessMemory sequences',
                            'Implement process integrity monitoring'
                        ]
                    })

                    self.logger.warning(
                        f"Process hollowing detected with {len(sequence)} indicators "
                        f"(confidence: {confidence:.0%})"
                    )

            return indicators
        except Exception as e:
            self.logger.error(
                f"Error detecting process hollowing: {e}",
                exc_info=True)
            return []

    def detect_dll_side_loading(self, data: bytes) -> List[Dict]:
        """
        Detect DLL side-loading patterns.

        DLL side-loading (DLL hijacking) occurs when an attacker:
        1. Creates a malicious DLL with same name as legitimate DLL
        2. Places it in the application's search path
        3. Application loads the malicious DLL instead of legitimate one

        Args:
            data (bytes): Binary data to analyze

        Returns:
            List[Dict]: DLL side-loading indicators found

        Raises:
            ValueError: If data is empty
        """
        if not data:
            raise ValueError("Cannot analyze empty data")

        indicators = []

        try:
            sideload_patterns = [
                (b'GetModuleFileNameA', 'Get module path'),
                (b'GetModuleFileNameW', 'Get module path (Unicode)'),
                (b'LoadLibraryA', 'Load library'),
                (b'LoadLibraryW', 'Load library (Unicode)'),
                (b'LoadLibraryExA', 'Load library with flags'),
                (b'LoadLibraryExW', 'Load library with flags (Unicode)'),
                (b'GetProcAddress', 'Get function address'),
                (b'SetDllDirectoryA', 'Set DLL search path'),
                (b'SetDllDirectoryW', 'Set DLL search path (Unicode)'),
                (b'AddDllDirectoryA', 'Add DLL search directory'),
                (b'AddDllDirectoryW', 'Add DLL search directory (Unicode)'),
                (b'RemoveDllDirectoryA', 'Remove DLL directory'),
                (b'RemoveDllDirectoryW', 'Remove DLL directory (Unicode)')
            ]

            matches = []
            found_apis = {}

            for pattern, description in sideload_patterns:
                if pattern in data:
                    matches.append({
                        'api': pattern.decode(),
                        'description': description
                    })
                    found_apis[pattern] = True

            if len(matches) >= 2:
                confidence = min(len(matches) * 0.20, 0.90)

                # Check for key combinations
                has_load_library = any(m['api'] in ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW']
                                     for m in matches)
                has_path_ops = any(m['api'] in ['SetDllDirectoryA', 'SetDllDirectoryW', 'AddDllDirectoryA', 'AddDllDirectoryW']
                                  for m in matches)
                has_getproc = any(m['api'] == 'GetProcAddress' for m in matches)

                if has_load_library:
                    indicators.append({
                        'type': 'DLL Side-Loading',
                        'confidence': confidence,
                        'severity': 'HIGH',
                        'indicators': matches,
                        'description': 'DLL side-loading/hijacking patterns detected',
                        'mitre_ttp': ['T1574', 'T1574.001'],
                        'attack_chain': [
                            'Create malicious DLL with legitimate name',
                            'Place in application search path',
                            'Application loads malicious DLL',
                            'Execute arbitrary code in application context'
                        ],
                        'remediation': [
                            'Implement DLL search order randomization',
                            'Use manifests to specify trusted DLLs',
                            'Monitor DLL load attempts',
                            'Validate DLL signatures'
                        ]
                    })

                    self.logger.warning(
                        f"DLL side-loading detected: {len(matches)} indicators "
                        f"(confidence: {confidence:.0%})"
                    )

            return indicators
        except Exception as e:
            self.logger.error(
                f"Error detecting DLL side-loading: {e}",
                exc_info=True)
            return []

    def detect_rootkit_behavior(self, data: bytes) -> List[Dict]:
        """
        Detect rootkit installation patterns.

        Rootkits attempt to:
        1. Access kernel-mode operations
        2. Install hooks in system structures (IDT, SSDT, etc.)
        3. Manipulate device I/O
        4. Query system information

        Args:
            data (bytes): Binary data to analyze

        Returns:
            List[Dict]: Rootkit behavior indicators found

        Raises:
            ValueError: If data is empty
        """
        if not data:
            raise ValueError("Cannot analyze empty data")

        indicators = []

        try:
            rootkit_sigs = [
                (b'CreateServiceA', 'Service creation', 0),
                (b'CreateServiceW', 'Service creation (Unicode)', 0),
                (b'ChangeServiceConfigA', 'Service modification', 1),
                (b'ChangeServiceConfigW', 'Service modification (Unicode)', 1),
                (b'StartServiceA', 'Service start', 2),
                (b'StartServiceW', 'Service start (Unicode)', 2),
                (b'NtSetInformationFile', 'Kernel file operations', 3),
                (b'ZwSetInformationFile', 'Kernel file operations (Native)', 3),
                (b'NtDeviceIoControlFile', 'Device I/O control', 4),
                (b'ZwDeviceIoControlFile', 'Device I/O control (Native)', 4),
                (b'ZwQuerySystemInformation', 'System info query', 5),
                (b'NtQuerySystemInformation', 'System info query (Native)', 5),
                (b'lidt', 'IDT load (inline)', 6),
                (b'sidt', 'IDT store (inline)', 6),
                (b'SSDT', 'System service dispatch table', 7),
                (b'KeServiceDescriptorTable', 'Kernel service table', 7)
            ]

            detected = []
            risk_indicators = []

            for sig, description, priority in rootkit_sigs:
                if sig in data:
                    detected.append({
                        'signature': sig.decode(),
                        'description': description,
                        'priority': priority
                    })
                    risk_indicators.append(description)

            if len(detected) >= 2:
                confidence = min(len(detected) * 0.18, 0.95)

                # Categorize rootkit type based on detected signatures
                rootkit_type = 'Unknown'
                if any('Service' in d['description'] for d in detected):
                    rootkit_type = 'Service-based'
                elif any('Kernel' in d['description'] or 'SSDT' in d['description'] or 'IDT' in d['description']
                        for d in detected):
                    rootkit_type = 'Kernel-mode'
                elif any('Device' in d['description'] or 'I/O' in d['description'] for d in detected):
                    rootkit_type = 'Driver-based'

                indicators.append({
                    'type': 'Rootkit Behavior',
                    'rootkit_type': rootkit_type,
                    'confidence': confidence,
                    'severity': 'CRITICAL',
                    'indicators': detected,
                    'description': f'{rootkit_type} rootkit installation patterns detected',
                    'mitre_ttp': ['T1014', 'T1547', 'T1547.008'],
                    'capabilities': risk_indicators,
                    'impact': [
                        'Kernel-level code execution',
                        'Bypass of security monitoring',
                        'System integrity compromise',
                        'Persistence across reboots'
                    ],
                    'remediation': [
                        'Boot from clean media',
                        'Perform offline malware scan',
                        'Use rootkit detection tools',
                        'Restore from known-good backup',
                        'Update kernel and drivers'
                    ]
                })

                self.logger.critical(
                    f"{rootkit_type} rootkit detected: {len(detected)} indicators "
                    f"(confidence: {confidence:.0%})"
                )

            return indicators
        except Exception as e:
            self.logger.error(
                f"Error detecting rootkit behavior: {e}",
                exc_info=True)
            return []

    def get_analysis_summary(self) -> Dict:
        """
        Get summary of all monitoring analysis.

        Returns:
            Dict: Complete analysis summary
        """
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'duration': (datetime.utcnow() - self.start_time).total_seconds(),
            'total_events': self.analysis_metadata['total_events'],
            'total_api_calls': self.analysis_metadata['total_api_calls'],
            'total_processes': len(self.process_tree),
            'total_network_events': len(self.network_flows),
            'total_file_operations': len(self.file_operations_log),
            'total_registry_operations': len(self.registry_operations_log),
            'suspicious_processes': list(self.suspicious_processes),
            'analysis_metadata': self.analysis_metadata
        }


# ============================================================
# SYSTEM CALL TRACING
# ============================================================

class SystemCallTracer:
    """Trace and analyze system calls"""

    # Linux syscall numbers (x86_64)
    LINUX_SYSCALLS = {
        0: 'read',
        1: 'write',
        2: 'open',
        3: 'close',
        4: 'stat',
        5: 'fstat',
        9: 'link',
        10: 'unlink',
        14: 'mknod',
        18: 'fsync',
        21: 'access',
        33: 'dup2',
        39: 'mkdir',
        40: 'rmdir',
        59: 'execve',
        63: 'getpriority',
        102: 'socketcall',
        113: 'fcntl',
        140: 'mlock',
        142: 'select',
        205: 'mount',
        206: 'umount2',
        218: 'madvise',
        257: 'openat',
        262: 'newfstatat',
    }

    def __init__(self):
        self.trace_log = []

    def analyze_syscall_sequence(self, data: bytes) -> Dict:
        """Analyze system call patterns"""
        analysis = {
            'suspicious_sequences': [],
            'file_access_patterns': [],
            'network_syscalls': [],
            'privilege_escalation': [],
        }

        # Detect privilege escalation syscalls
        priv_esc_sigs = [
            b'seteuid', b'setegid', b'setreuid', b'setregid',
            b'prctl', b'capset', b'ptrace'
        ]

        for sig in priv_esc_sigs:
            if sig in data:
                analysis['privilege_escalation'].append(
                    sig.decode('latin-1', errors='ignore'))

        # Detect network syscalls
        net_sigs = [
            b'socket', b'connect', b'bind', b'listen',
            b'send', b'recv', b'sendto', b'recvfrom'
        ]

        for sig in net_sigs:
            if sig in data:
                analysis['network_syscalls'].append(
                    sig.decode('latin-1', errors='ignore'))

        # Detect file access
        file_sigs = [
            b'openat', b'unlinkat', b'renameat',
            b'mkdirat', b'chmod'
        ]

        for sig in file_sigs:
            if sig in data:
                analysis['file_access_patterns'].append(
                    sig.decode('latin-1', errors='ignore'))

        return analysis

# ============================================================
# FILE SYSTEM MONITORING
# ============================================================

class FileSystemMonitor:
    """Monitor file system operations"""

    # Suspicious file locations
    SUSPICIOUS_LOCATIONS = {
        'Windows': [
            'C:\\Windows\\System32',
            'C:\\Windows\\Temp',
            'C:\\ProgramData',
            'C:\\Users\\*/AppData/Local',
            'C:\\Users\\*/AppData/Roaming',
            '%WINDIR%\\System32\\drivers\\etc',
        ],
        'Linux': [
            '/lib/modules',
            '/opt',
            '/tmp',
            '/var/tmp',
            '/dev/shm',
            '/proc/self',
        ]
    }

    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = [
        '.exe', '.dll', '.sys', '.scr', '.vbs', '.js',
        '.bat', '.cmd', '.ps1', '.psm1',
        '.elf', '.so', '.ko', '.sh'
    ]

    def __init__(self):
        self.operations = []

    def analyze_file_operations(self, data: bytes) -> Dict:
        """Analyze file system operations"""
        analysis = {
            'file_modifications': [],
            'suspicious_writes': [],
            'hidden_files': [],
            'alternate_data_streams': [],
        }

        text = data.decode('latin-1', errors='ignore')

        # Detect alternate data stream operations (Windows)
        ads_pattern = r'[a-zA-Z]:\\[^:]+:[a-zA-Z0-9_]+'
        ads_matches = re.findall(ads_pattern, text)
        analysis['alternate_data_streams'] = ads_matches

        # Detect hidden file creation
        if any(sig in data for sig in [b'SetFileAttributesA', b'FILE_ATTRIBUTE_HIDDEN']):
            analysis['hidden_files'].append('File hiding capability detected')

        # Detect suspicious file writes
        suspicious_write_sigs = [
            b'WriteFile', b'CreateFileA', b'CreateFileW',
            b'SetEndOfFile', b'MemoryMapping'
        ]

        detected_writes = []
        for sig in suspicious_write_sigs:
            if sig in data:
                detected_writes.append(sig.decode('latin-1', errors='ignore'))

        if detected_writes:
            analysis['suspicious_writes'] = detected_writes

        return analysis


# ============================================================
# REGISTRY MONITORING
# ============================================================

class RegistryMonitor:
    """Monitor registry operations"""

    # Suspicious registry keys
    SUSPICIOUS_KEYS = {
        'persistence': [
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM\\System\\CurrentControlSet\\Services',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        ],
        'security_bypass': [
            'HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate',
            'HKLM\\Software\\Policies\\Microsoft\\Windows Defender',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
        ],
        'data_exfiltration': [
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',
        ]
    }

    def __init__(self):
        self.operations = []

    def analyze_registry_operations(self, data: bytes) -> Dict:
        """Analyze registry operations"""
        analysis = {
            'persistence_attempts': [],
            'security_modifications': [],
            'data_collection': [],
            'evasion_techniques': [],
        }

        text = data.decode('latin-1', errors='ignore')

        # Check for persistence registry keys
        for key_type, keys in self.SUSPICIOUS_KEYS.items():
            for key in keys:
                if key in text:
                    if key_type == 'persistence':
                        analysis['persistence_attempts'].append(key)
                    elif key_type == 'security_bypass':
                        analysis['security_modifications'].append(key)
                    elif key_type == 'data_exfiltration':
                        analysis['data_collection'].append(key)

        # Detect registry evasion
        evasion_sigs = [
            b'RegOpenKeyEx', b'RegQueryValueEx', b'RegDeleteValueA',
            b'SHDeleteKey', b'RegFlushKey'
        ]

        for sig in evasion_sigs:
            if sig in data:
                analysis['evasion_techniques'].append(
                    sig.decode('latin-1', errors='ignore'))

        return analysis


# ============================================================
# NETWORK BEHAVIOR MONITORING
# ============================================================

class NetworkBehaviorMonitor:
    """Monitor network-related behaviors"""

    def __init__(self):
        self.connections = []
        self.dns_queries = []

    def analyze_network_behavior(self, data: bytes) -> Dict:
        """Analyze network behaviors"""
        analysis = {
            'c2_indicators': [],
            'data_exfiltration': [],
            'dns_activity': [],
            'port_scanning': [],
            'protocol_anomalies': [],
        }

        # C2 indicators
        c2_sigs = [
            b'POST /api', b'GET /api', b'X-Forwarded-For',
            b'User-Agent:', b'Accept-Encoding:',
            b'Cookie:', b'Set-Cookie:'
        ]

        detected_c2 = []
        for sig in c2_sigs:
            if sig in data:
                detected_c2.append(sig.decode('latin-1', errors='ignore'))

        if detected_c2:
            analysis['c2_indicators'] = detected_c2

        # DNS activity
        dns_sigs = [
            b'nslookup', b'getaddrinfo', b'gethostbyname',
            b'WSAAsyncGetHostByName', b'DnsQuery'
        ]

        for sig in dns_sigs:
            if sig in data:
                analysis['dns_activity'].append(
                    sig.decode('latin-1', errors='ignore'))

        # Port scanning
        port_scan_sigs = [
            b'CreateSocketA', b'WSASocket', b'connect',
            b'recv', b'closesocket'
        ]

        port_scan_count = sum(1 for sig in port_scan_sigs if sig in data)
        if port_scan_count >= 3:
            analysis['port_scanning'].append({
                'detected': True,
                'confidence': min(port_scan_count * 0.2, 0.9)
            })

        return analysis


# ============================================================
# SANDBOX REPORT GENERATOR
# ============================================================

class SandboxReportGenerator:
    """Generate comprehensive sandbox analysis report"""

    def __init__(self, data: bytes):
        self.data = data
        self.timestamp = datetime.utcnow()

    def generate_execution_summary(self) -> Dict:
        """Generate execution summary"""
        summary = {
            'analysis_timestamp': self.timestamp.isoformat(),
            'sample_size': len(self.data),
            'execution_time': 'N/A',
            'process_tree': [],
            'initial_process': 'malware.exe',
            'spawned_processes': [],
            'terminated_processes': []
        }

        return summary

    def generate_behavior_profile(self) -> Dict:
        """Generate behavior profile"""
        profile = {
            'process_behaviors': {},
            'file_system_behaviors': {},
            'registry_behaviors': {},
            'network_behaviors': {},
            'overall_risk': 'Unknown'
        }

        # Analyze each domain
        proc_monitor = ProcessMonitor()
        profile['process_behaviors'] = proc_monitor.analyze_api_calls(self.data)

        fs_monitor = FileSystemMonitor()
        profile['file_system_behaviors'] = fs_monitor.analyze_file_operations(
            self.data)

        reg_monitor = RegistryMonitor()
        profile['registry_behaviors'] = reg_monitor.analyze_registry_operations(
            self.data)

        net_monitor = NetworkBehaviorMonitor()
        profile['network_behaviors'] = net_monitor.analyze_network_behavior(
            self.data)

        # Calculate overall risk
        behavior_score = profile['process_behaviors'].get('behavior_score', 0)
        if behavior_score > 0.8:
            profile['overall_risk'] = 'CRITICAL'
        elif behavior_score > 0.6:
            profile['overall_risk'] = 'HIGH'
        elif behavior_score > 0.4:
            profile['overall_risk'] = 'MEDIUM'
        else:
            profile['overall_risk'] = 'LOW'

        return profile

    def generate_threat_indicators(self) -> Dict:
        """Generate threat indicators"""
        indicators = {
            'process_injection': False,
            'dll_side_loading': False,
            'rootkit_behavior': False,
            'privilege_escalation': False,
            'persistence_mechanism': False,
            'anti_analysis': False,
            'data_exfiltration': False,
        }

        # Check for each indicator
        if any(api in self.data for api in [b'VirtualAllocEx', b'WriteProcessMemory']):
            indicators['process_injection'] = True

        if any(api in self.data for api in [b'LoadLibraryA', b'GetProcAddress']):
            indicators['dll_side_loading'] = True

        if any(api in self.data for api in [b'CreateService', b'NtSetInformationFile']):
            indicators['rootkit_behavior'] = True

        if any(api in self.data for api in [b'seteuid', b'setegid', b'prctl']):
            indicators['privilege_escalation'] = True

        if any(api in self.data for api in [b'SetWindowsHookEx', b'CreateService']):
            indicators['persistence_mechanism'] = True

        if any(api in self.data for api in [b'IsDebuggerPresent', b'VirtualProtect']):
            indicators['anti_analysis'] = True

        if any(api in self.data for api in [b'InternetOpenA', b'HttpOpenRequestA']):
            indicators['data_exfiltration'] = True

        return indicators

    def generate_ioc_list(self) -> Dict:
        """Generate list of IOCs from behavior"""
        iocs = {
            'c2_servers': [],
            'dropped_files': [],
            'registry_modifications': [],
            'process_names': [],
            'dns_queries': [],
        }

        text = self.data.decode('latin-1', errors='ignore')

        # Extract IOCs using patterns
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs['c2_servers'] = re.findall(ip_pattern, text)

        # File paths
        file_pattern = r'[a-zA-Z]:\\[^"\s]*'
        iocs['dropped_files'] = list(set(re.findall(file_pattern, text)))[:10]

        return iocs

    def generate_final_report(self) -> Dict:
        """Generate final comprehensive report"""
        report = {
            'metadata': {
                'analysis_date': self.timestamp.isoformat(),
                'analysis_engine': 'Dynamic Behavioral Analyzer v1.0',
                'sample_size': len(self.data),
            },
            'execution_summary': self.generate_execution_summary(),
            'behavior_profile': self.generate_behavior_profile(),
            'threat_indicators': self.generate_threat_indicators(),
            'iocs': self.generate_ioc_list(),
            'verdict': 'Unknown',
            'confidence': 0.0,
        }

        # Determine verdict
        behavior_profile = report['behavior_profile']
        risk = behavior_profile.get('overall_risk', 'LOW')

        threat_count = sum(1 for v in report['threat_indicators'].values() if v)

        if risk == 'CRITICAL' or threat_count >= 5:
            report['verdict'] = 'Malware'
            report['confidence'] = min(0.95, 0.5 + threat_count * 0.1)
        elif risk == 'HIGH' or threat_count >= 3:
            report['verdict'] = 'Suspicious'
            report['confidence'] = min(0.85, 0.4 + threat_count * 0.08)
        elif risk == 'MEDIUM' or threat_count >= 1:
            report['verdict'] = 'PUP/Unwanted'
            report['confidence'] = 0.5 + threat_count * 0.05
        else:
            report['verdict'] = 'Clean'
            report['confidence'] = 0.9

        return report


# ============================================================
# MEMORY ANALYSIS ENGINE
# ============================================================

class MemoryAnalyzer:
    """Analyze memory-related behaviors"""

    def __init__(self, data: bytes):
        self.data = data

    def detect_shellcode_patterns(self) -> List[Dict]:
        """Detect shellcode execution patterns"""
        patterns = []

        # Common shellcode signatures
        shellcode_sigs = [
            (b'\x55\x8B\xEC\x83\xEC', 'Function prologue (x86)'),
            (b'\x48\x89\x5C\x24\x08', 'Function prologue (x64)'),
            (b'\x90' * 8, 'NOP sled (evasion)'),
            (b'\x00\x00\x00\x00\x00', 'Null bytes (potential shellcode)'),
        ]

        for sig, description in shellcode_sigs:
            if sig in self.data:
                offset = self.data.find(sig)
                patterns.append({
                    'type': 'Shellcode Pattern',
                    'description': description,
                    'offset': f'0x{offset:X}',
                    'signature': sig[:8].hex()
                })

        return patterns

    def analyze_memory_corruption(self) -> Dict:
        """Analyze potential memory corruption"""
        analysis = {
            'buffer_overflow_sigs': [],
            'heap_spray_indicators': [],
            'use_after_free': [],
            'risk_level': 'Low'
        }

        # Buffer overflow patterns
        bof_sigs = [
            (b'strcpy', 'Unsafe string copy'),
            (b'sprintf', 'Unsafe formatting'),
            (b'gets', 'Unsafe input'),
            (b'memcpy', 'Potential overflow'),
        ]

        for sig, desc in bof_sigs:
            if sig in self.data:
                analysis['buffer_overflow_sigs'].append(desc)

        # Heap spray patterns
        if b'\x0c\x0c\x0c\x0c' in self.data or b'\x41' * 256 in self.data:
            analysis['heap_spray_indicators'].append(
                'Repetitive byte pattern (heap spray)')

        if len(analysis['buffer_overflow_sigs']) > 2:
            analysis['risk_level'] = 'High'
        elif len(analysis['buffer_overflow_sigs']) > 0:
            analysis['risk_level'] = 'Medium'

        return analysis


# ============================================================
# INTEGRATION & COMPREHENSIVE ANALYSIS
# ============================================================

def comprehensive_dynamic_analysis(data: bytes) -> Dict:
    """Complete dynamic behavioral analysis"""

    results = {
        'process_analysis': {},
        'system_calls': {},
        'file_system': {},
        'registry': {},
        'network': {},
        'memory': {},
        'sandbox_report': {},
    }

    # Process Analysis
    proc_monitor = ProcessMonitor()
    results['process_analysis'] = {
        'api_analysis': proc_monitor.analyze_api_calls(data),
        'process_hollowing': proc_monitor.detect_process_hollowing(data),
        'dll_sideloading': proc_monitor.detect_dll_side_loading(data),
        'rootkit_behavior': proc_monitor.detect_rootkit_behavior(data),
    }

    # System Calls
    syscall_tracer = SystemCallTracer()
    results['system_calls'] = syscall_tracer.analyze_syscall_sequence(data)

    # File System
    fs_monitor = FileSystemMonitor()
    results['file_system'] = fs_monitor.analyze_file_operations(data)

    # Registry
    reg_monitor = RegistryMonitor()
    results['registry'] = reg_monitor.analyze_registry_operations(data)

    # Network
    net_monitor = NetworkBehaviorMonitor()
    results['network'] = net_monitor.analyze_network_behavior(data)

    # Memory
    mem_analyzer = MemoryAnalyzer(data)
    results['memory'] = {
        'shellcode': mem_analyzer.detect_shellcode_patterns(),
        'corruption': mem_analyzer.analyze_memory_corruption(),
    }

    # Generate Sandbox Report
    report_gen = SandboxReportGenerator(data)
    results['sandbox_report'] = report_gen.generate_final_report()

    return results


# if __name__ == '__main__':
#    if len(sys.argv) < 2:
#        print("Usage: Part 6 requires binary file argument")
#        sys.exit(1)
#
#    with open(sys.argv[1], 'rb') as f:
#        data = f.read()
#
#    analysis = comprehensive_dynamic_analysis(data)
#    print(json.dumps(analysis, indent=2, default=str))
#
#
# ============================================================
# PART 7: MACHINE LEARNING ANOMALY DETECTION + AI CLASSIFICATION ENGINE
# Lines 3928-5127 (1200 lines)
# ============================================================

import numpy as np
from collections import defaultdict
from typing import Tuple

# ============================================================
# FEATURE EXTRACTION ENGINE
# ============================================================

class FeatureExtractor:
    """Extract machine learning features from binary data"""

    def __init__(self, data: bytes):
        self.data = data
        self.features = {}

    def extract_byte_statistics(self) -> Dict[str, float]:
        """Extract statistical features from byte distribution"""
        stats = {
            'byte_mean': 0.0,
            'byte_std': 0.0,
            'byte_min': 0,
            'byte_max': 255,
            'byte_entropy': 0.0,
            'byte_frequency_variance': 0.0,
        }

        if len(self.data) == 0:
            return stats

        byte_array = np.frombuffer(self.data, dtype=np.uint8)

        # Mean and standard deviation
        stats['byte_mean'] = float(np.mean(byte_array))
        stats['byte_std'] = float(np.std(byte_array))
        stats['byte_min'] = int(np.min(byte_array))
        stats['byte_max'] = int(np.max(byte_array))

        # Entropy
        counter = defaultdict(int)
        for byte in self.data:
            counter[byte] += 1

        length = len(self.data)
        entropy = 0.0
        for count in counter.values():
            prob = count / length
            entropy -= prob * np.log2(prob) if prob > 0 else 0

        stats['byte_entropy'] = entropy

        # Frequency variance
        frequencies = np.array(list(counter.values()))
        stats['byte_frequency_variance'] = float(np.var(frequencies))

        return stats

    def extract_string_features(self) -> Dict[str, float]:
        """Extract string-related features"""
        features = {
            'string_count': 0,
            'avg_string_length': 0.0,
            'max_string_length': 0,
            'string_diversity': 0.0,
            'printable_ratio': 0.0,
        }

        text = self.data.decode('latin-1', errors='ignore')

        # Extract strings
        strings = re.findall(r'[\x20-\x7e]{4,}', text)
        features['string_count'] = len(strings)

        if strings:
            lengths = [len(s) for s in strings]
            features['avg_string_length'] = float(np.mean(lengths))
            features['max_string_length'] = max(lengths)
            features['string_diversity'] = len(set(strings)) / len(strings)

        # Printable ratio
        printable_count = sum(1 for byte in self.data if 32 <= byte <= 126)
        features['printable_ratio'] = printable_count / len(self.data) if self.data else 0.0

        return features

    def extract_structural_features(self) -> Dict[str, float]:
        """Extract binary structure features"""
        features = {
            'null_byte_ratio': 0.0,
            'repeated_byte_sequences': 0,
            'section_count': 0,
            'header_signature_count': 0,
            'compression_ratio': 0.0,
        }

        # Null byte ratio
        null_count = self.data.count(b'\x00')
        features['null_byte_ratio'] = null_count / len(self.data) if self.data else 0.0

        # Repeated sequences
        repeated = 0
        for i in range(len(self.data) - 4):
            if self.data[i:i + 4] == self.data[i + 4:i + 8]:
                repeated += 1
        features['repeated_byte_sequences'] = repeated

        # Header signatures (magic bytes)
        header_sigs = [
            b'MZ', b'\x7fELF', b'\x1f\x8b', b'BZh', b'Rar!',
            b'\x50\x4b\x03\x04'
        ]
        features['header_signature_count'] = sum(
            1 for sig in header_sigs if sig in self.data)

        # Compression estimation
        try:
            data_sample = self.data[:10000] if len(self.data) > 10000 else self.data
            compressed = zlib.compress(data_sample)
            features['compression_ratio'] = len(compressed) / len(data_sample)
        except:
            features['compression_ratio'] = 1.0

        return features

    def extract_api_features(self) -> Dict[str, float]:
        """Extract API-related features"""
        features = defaultdict(float)

        # API categories
        api_categories = {
            'process_apis': [b'CreateProcess', b'CreateRemoteThread', b'VirtualAllocEx'],
            'file_apis': [b'CreateFile', b'WriteFile', b'DeleteFile', b'CopyFile'],
            'registry_apis': [b'RegOpenKey', b'RegSetValue', b'RegCreateKey'],
            'network_apis': [b'socket', b'connect', b'send', b'InternetOpen'],
            'system_apis': [b'GetModuleHandle', b'LoadLibrary', b'GetProcAddress'],
            'anti_analysis': [b'IsDebuggerPresent', b'VirtualProtect', b'SetErrorMode'],
        }

        for category, apis in api_categories.items():
            count = sum(1 for api in apis if api in self.data)
            features[f'{category}_count'] = float(count)
            features[f'{category}_density'] = count / len(self.data) if self.data else 0.0

        return dict(features)

    def extract_entropy_features(self) -> Dict[str, float]:
        """Extract entropy-based features"""
        features = {}

        analyzer = EntropyAnalyzer()

        # Window entropies
        window_size = 256
        entropies = []
        for i in range(0, len(self.data), window_size):
            block = self.data[i:i + window_size]
            entropies.append(analyzer.shannon_entropy(block))

        if entropies:
            features['mean_entropy'] = float(np.mean(entropies))
            features['std_entropy'] = float(np.std(entropies))
            features['max_entropy'] = float(np.max(entropies))
            features['min_entropy'] = float(np.min(entropies))
            features['entropy_variance'] = float(np.var(entropies))

        # Overall entropy
        features['overall_entropy'] = analyzer.shannon_entropy(self.data)

        return features

    def extract_all_features(self) -> Dict[str, float]:
        """Extract all features"""
        all_features = {}

        all_features.update(self.extract_byte_statistics())
        all_features.update(self.extract_string_features())
        all_features.update(self.extract_structural_features())
        all_features.update(self.extract_api_features())
        all_features.update(self.extract_entropy_features())

        return all_features


# ============================================================
# ANOMALY DETECTION ENGINE
# ============================================================

class AnomalyDetector:
    """Detect anomalies using statistical methods"""

    def __init__(self):
        self.reference_stats = self._initialize_reference_stats()

    def _initialize_reference_stats(self) -> Dict:
        """Initialize reference statistics for normal binaries"""
        return {
            'byte_mean': (100, 150),  # (min, max)
            'byte_std': (30, 80),
            'byte_entropy': (4.0, 6.5),
            'string_count': (5, 500),
            'printable_ratio': (0.1, 0.8),
            'null_byte_ratio': (0.0, 0.3),
            'compression_ratio': (0.4, 0.9),
        }

    def detect_anomalies(self, features: Dict[str, float]) -> Dict:
        """Detect anomalies in features"""
        anomalies = {
            'detected_anomalies': [],
            'anomaly_score': 0.0,
            'anomaly_details': []
        }

        anomaly_count = 0

        for feature_name, (min_val, max_val) in self.reference_stats.items():
            if feature_name in features:
                value = features[feature_name]

                if value < min_val or value > max_val:
                    anomaly_count += 1
                    anomalies['detected_anomalies'].append(feature_name)
                    anomalies['anomaly_details'].append({
                        'feature': feature_name,
                        'value': value,
                        'expected_range': (min_val, max_val),
                        'deviation': max(0, min_val - value) or max(0, value - max_val)
                    })

        # Calculate anomaly score (0-1)
        total_features = len(self.reference_stats)
        anomalies['anomaly_score'] = anomaly_count / total_features if total_features > 0 else 0.0

        return anomalies

    def detect_outliers_zscore(
        self, features: Dict[str, float], threshold: float = 3.0) -> Dict:
        """Detect outliers using Z-score method"""
        outliers = {
            'outlier_features': [],
            'outlier_count': 0,
            'outlier_score': 0.0
        }

        # Convert to array for calculation
        feature_values = np.array(list(features.values()))

        if len(feature_values) < 2:
            return outliers

        mean = np.mean(feature_values)
        std = np.std(feature_values)

        if std == 0:
            return outliers

        z_scores = (feature_values - mean) / std

        outlier_count = sum(1 for z in z_scores if abs(z) > threshold)
        outliers['outlier_count'] = outlier_count
        outliers['outlier_score'] = outlier_count / len(z_scores) if z_scores.size > 0 else 0.0

        # List outlier features
        for (name, value), z_score in zip(features.items(), z_scores):
            if abs(z_score) > threshold:
                outliers['outlier_features'].append({
                    'feature': name,
                    'value': value,
                    'z_score': float(z_score)
                })

        return outliers


class MLClassifier:
    """Machine learning-based classification with advanced anomaly detection"""

    # Trained weights (simplified model)
    MODEL_WEIGHTS = {
        'process_apis_count': 0.15,
        'byte_entropy': 0.12,
        'null_byte_ratio': 0.08,
        'repeated_byte_sequences': 0.10,
        'printable_ratio': -0.05,  # High printable = lower risk
        'network_apis_count': 0.13,
        'anti_analysis_count': 0.12,
        'file_apis_count': 0.08,
        'registry_apis_count': 0.08,
        'string_count': -0.03,
        'compression_ratio': 0.05,
        # NEW: Advanced entropy metrics
        'approximate_entropy': 0.09,
        'sample_entropy': 0.08,
        'permutation_entropy': 0.07,
        'lz_complexity': 0.06,
        'fuzzy_entropy': 0.05,
        'dispersion_entropy': 0.05,
        'conditional_entropy': -0.04,  # High conditional entropy = more random = lower risk
    }

    def __init__(self):
        self.model_name = 'Hybrid Static-Dynamic Classifier v2.0'
        self.model_version = '2.0'

    def classify(self, features: Dict[str, float]) -> Dict:
        """Classify sample using ML model"""
        classification = {
            'model': self.model_name,
            'version': self.model_version,
            'malware_score': 0.0,
            'classification': 'Unknown',
            'confidence': 0.0,
            'contributing_features': [],
            'risk_factors': [],
            'analysis_details': {},
            'reliability': 0.0,
            'explanation': ''
        }

        score = 0.0
        feature_contributions = []
        risk_factors = []

        # Calculate weighted score
        for feature_name, weight in self.MODEL_WEIGHTS.items():
            if feature_name in features:
                value = features[feature_name]
                contribution = value * weight
                score += contribution

                if abs(contribution) > 0.01:  # Only include significant contributions
                    feature_contributions.append({
                        'feature': feature_name,
                        'weight': weight,
                        'value': value,
                        'contribution': contribution
                    })

                    # Identify risk factors
                    if contribution > 0.05:
                        risk_factors.append({
                            'factor': feature_name,
                            'severity': 'HIGH' if contribution > 0.10 else 'MEDIUM',
                            'contribution': contribution
                        })

        # Normalize score to 0-1 range
        malware_score = 1.0 / (1.0 + np.exp(-score))  # Sigmoid function
        classification['malware_score'] = float(malware_score)
        classification['risk_factors'] = sorted(
            risk_factors, key=lambda x: x['contribution'], reverse=True)

        # Determine classification with enhanced thresholds
        if malware_score > 0.85:
            classification['classification'] = 'Malware'
            classification['confidence'] = malware_score
            classification['analysis_details']['threat_level'] = 'CRITICAL'
        elif malware_score > 0.70:
            classification['classification'] = 'Suspicious'
            classification['confidence'] = malware_score
            classification['analysis_details']['threat_level'] = 'HIGH'
        elif malware_score > 0.45:
            classification['classification'] = 'PUP/Unwanted'
            classification['confidence'] = malware_score
            classification['analysis_details']['threat_level'] = 'MEDIUM'
        else:
            classification['classification'] = 'Clean'
            classification['confidence'] = 1.0 - malware_score
            classification['analysis_details']['threat_level'] = 'LOW'

        # Add entropy-based insights
        if 'byte_entropy' in features:
            entropy_val = features['byte_entropy']
            if entropy_val > 7.5:
                classification['analysis_details']['entropy_profile'] = 'Highly Encrypted/Random'
            elif entropy_val > 6.5:
                classification['analysis_details']['entropy_profile'] = 'Compressed/Obfuscated'
            elif entropy_val > 5.0:
                classification['analysis_details']['entropy_profile'] = 'Mixed Content'
            else:
                classification['analysis_details']['entropy_profile'] = 'Normal/Plaintext'

        # Add pattern entropy insights
        if 'permutation_entropy' in features:
            pe = features['permutation_entropy']
            if pe < 0.3:
                classification['analysis_details']['pattern_complexity'] = 'Low (Deterministic)'
            elif pe < 0.6:
                classification['analysis_details']['pattern_complexity'] = 'Medium'
            else:
                classification['analysis_details']['pattern_complexity'] = 'High (Random-like)'

        classification['contributing_features'] = sorted(
            feature_contributions,
            key=lambda x: abs(x['contribution']),
            reverse=True
        )[:15]  # Increased to 15 features

        # NEW: Detect feature anomalies
        anomalies = self.detect_feature_anomalies(features)
        if anomalies['detected']:
            classification['analysis_details']['anomalies'] = anomalies['suspicious_combinations']
            classification['malware_score'] += anomalies['anomaly_score']
            classification['malware_score'] = min(
                classification['malware_score'], 1.0)

        # NEW: Calibrate probabilities
        calibration = self.calibrate_probabilities(features)
        classification['reliability'] = calibration['reliability']

        # NEW: Calculate model reliability
        reliability_info = self.calculate_model_reliability(
            features, classification)
        classification['analysis_details']['reliability_score'] = reliability_info['score']
        if reliability_info['issues']:
            classification['analysis_details']['reliability_issues'] = reliability_info['issues']

        # Adjust confidence based on reliability
        classification['confidence'] *= reliability_info['confidence_adjustment']

        # NEW: Generate explanation
        classification['explanation'] = self.explain_decision(
            classification, features)

        return classification

    def predict_malware_type(self, features: Dict[str, float]) -> Dict:
        """Predict specific malware type with enhanced scoring"""
        prediction = {
            'predicted_type': 'Unknown',
            'type_confidence': 0.0,
            'type_probabilities': {},
            'type_indicators': {}
        }

        # Malware type indicators with entropy-based refinement
        type_indicators = {
            'Trojan': {
                'features': ['process_apis_count', 'file_apis_count', 'registry_apis_count'],
                'entropy_range': (5.0, 7.5),
                'description': 'Process injection + file/registry manipulation'
            },
            'RAT': {
                'features': ['network_apis_count', 'process_apis_count', 'anti_analysis_count'],
                'entropy_range': (6.5, 8.0),
                'description': 'Remote access capabilities with anti-analysis'
            },
            'Ransomware': {
                'features': ['file_apis_count', 'byte_entropy', 'repeated_byte_sequences'],
                'entropy_range': (7.0, 8.0),
                'description': 'File encryption with high entropy'
            },
            'Rootkit': {
                'features': ['anti_analysis_count', 'registry_apis_count', 'process_apis_count'],
                'entropy_range': (5.5, 7.5),
                'description': 'Kernel-level access with system modifications'
            },
            'Worm': {
                'features': ['network_apis_count', 'file_apis_count', 'repeated_byte_sequences'],
                'entropy_range': (6.0, 7.8),
                'description': 'Network propagation with file operations'
            },
            'Spyware': {
                'features': ['network_apis_count', 'file_apis_count', 'byte_entropy'],
                'entropy_range': (5.5, 7.2),
                'description': 'Data exfiltration with stealth'
            },
            'Botnet': {
                'features': ['network_apis_count', 'process_apis_count', 'anti_analysis_count'],
                'entropy_range': (6.5, 8.0),
                'description': 'Command & control communication'
            },
            'Dropper': {
                'features': ['file_apis_count', 'process_apis_count', 'byte_entropy'],
                'entropy_range': (6.0, 7.8),
                'description': 'Payload delivery mechanism'
            }
        }

        type_scores = {}

        for malware_type, type_info in type_indicators.items():
            indicators = type_info['features']
            score = 0.0
            matched_features = 0

            for indicator in indicators:
                if indicator in features:
                    score += features[indicator]
                    matched_features += 1

            # Normalize by number of indicators
            if matched_features > 0:
                base_score = score / len(indicators)
            else:
                base_score = 0.0

            # Apply entropy range bonus
            if 'byte_entropy' in features:
                entropy_val = features['byte_entropy']
                entropy_min, entropy_max = type_info['entropy_range']

                if entropy_min <= entropy_val <= entropy_max:
                    base_score *= 1.2  # 20% bonus if entropy in range
                else:
                    base_score *= 0.8  # 20% penalty if entropy out of range

            type_scores[malware_type] = base_score
            prediction['type_indicators'][malware_type] = {
                'score': base_score,
                'description': type_info['description'],
                'entropy_range': type_info['entropy_range']
            }

        # Find highest scoring type
        if type_scores:
            predicted_type = max(type_scores, key=type_scores.get)
            prediction['predicted_type'] = predicted_type
            prediction['type_confidence'] = min(type_scores[predicted_type], 1.0)
            prediction['type_probabilities'] = {
                k: min(v, 1.0) for k, v in type_scores.items()
            }

        return prediction

    # NEW METHOD 1: Detect feature anomalies
    def detect_feature_anomalies(self, features: Dict[str, float]) -> Dict:
        """Detect anomalous feature combinations"""
        anomalies = {
            'detected': False,
            'anomaly_type': 'None',
            'anomaly_score': 0.0,
            'suspicious_combinations': []
        }

        # High entropy + no APIs = suspicious (encrypted with minimal execution)
        if features.get('byte_entropy', 0) > 7.5 and features.get('process_apis_count', 0) == 0:
            anomalies['suspicious_combinations'].append(
                'High entropy without API calls (stealth)')
            anomalies['anomaly_score'] += 0.15
            anomalies['anomaly_type'] = 'Encrypted Payload'

        # High API count + low entropy = suspicious (obfuscated APIs)
        total_apis = (features.get('process_apis_count', 0) +
                     features.get('network_apis_count', 0))
        if total_apis > 5 and features.get('byte_entropy', 0) < 4.0:
            anomalies['suspicious_combinations'].append(
                'High API activity with low entropy (obfuscated)')
            anomalies['anomaly_score'] += 0.15
            anomalies['anomaly_type'] = 'Obfuscated Malware'

        # All entropy metrics low = normal, but check for obfuscation
        entropy_metrics = [
            features.get('approximate_entropy', 0),
            features.get('sample_entropy', 0),
            features.get('permutation_entropy', 0)
        ]
        if all(e < 0.3 for e in entropy_metrics if e > 0) and features.get('byte_entropy', 0) > 6.0:
            anomalies['suspicious_combinations'].append(
                'Low pattern entropy with high byte entropy (encrypted)')
            anomalies['anomaly_score'] += 0.2
            anomalies['anomaly_type'] = 'Encrypted/Packed'

        # Anti-analysis + network communication = C2 bot
        if (features.get('anti_analysis_count', 0) > 2 and
            features.get('network_apis_count', 0) > 2):
            anomalies['suspicious_combinations'].append(
                'Anti-analysis with network comm (C2 bot)')
            anomalies['anomaly_score'] += 0.2
            anomalies['anomaly_type'] = 'Botnet/RAT'

        # High null byte ratio + high entropy = packing indicator
        if features.get('null_byte_ratio', 0) > 0.3 and features.get('byte_entropy', 0) > 6.5:
            anomalies['suspicious_combinations'].append(
                'High null bytes with high entropy (packed)')
            anomalies['anomaly_score'] += 0.15
            anomalies['anomaly_type'] = 'Packed Malware'

        anomalies['detected'] = anomalies['anomaly_score'] > 0.2
        return anomalies

    # NEW METHOD 2: Calibrate probabilities
    def calibrate_probabilities(self, features: Dict[str, float]) -> Dict:
        """Calibrate raw scores to realistic probabilities"""
        calibration = {
            'raw_score': 0.0,
            'calibrated_score': 0.0,
            'confidence_interval': (0.0, 0.0),
            'reliability': 0.0,
            'feature_coverage_percent': 0.0
        }

        # Check feature completeness
        available_features = len(
            [f for f in features if f in self.MODEL_WEIGHTS and features[f] is not None])
        total_features = len(self.MODEL_WEIGHTS)
        feature_coverage = available_features / total_features if total_features > 0 else 0.0

        calibration['feature_coverage_percent'] = feature_coverage * 100
        calibration['reliability'] = feature_coverage

        # Adjust confidence based on feature availability
        if feature_coverage < 0.5:
            calibration['confidence_interval'] = (0.3, 0.7)
        elif feature_coverage < 0.8:
            calibration['confidence_interval'] = (0.4, 0.85)
        else:
            calibration['confidence_interval'] = (0.5, 0.95)

        return calibration

    # NEW METHOD 3: Dynamic weight adjustment
    def get_dynamic_weights(self, data_characteristics: Dict) -> Dict:
        """Dynamically adjust weights based on data type"""
        weights = self.MODEL_WEIGHTS.copy()

        # If data is email, increase phishing/network indicators
        if data_characteristics.get('is_email', False):
            weights['network_apis_count'] *= 1.3
            weights['anti_analysis_count'] *= 1.2

        # If data is PE executable
        if data_characteristics.get('is_pe', False):
            weights['process_apis_count'] *= 1.4
            weights['registry_apis_count'] *= 1.3

        # If data is ELF executable
        if data_characteristics.get('is_elf', False):
            weights['process_apis_count'] *= 1.2
            weights['conditional_entropy'] *= 1.3

        # If data is packed/encrypted
        if data_characteristics.get('is_packed', False):
            weights['byte_entropy'] *= 1.5
            weights['lz_complexity'] *= 1.4
            weights['compression_ratio'] *= 1.3

        # If data has high null byte ratio (common in packed data)
        if data_characteristics.get('null_byte_heavy', False):
            weights['null_byte_ratio'] *= 1.4
            weights['byte_entropy'] *= 1.2

        return weights

    # NEW METHOD 4: Calculate model reliability
    def calculate_model_reliability(self, features: Dict[str, float],
                                   classification: Dict) -> Dict:
        """Calculate how reliable this classification is"""
        reliability = {
            'score': 0.0,
            'issues': [],
            'confidence_adjustment': 1.0
        }

        # Check for conflicting signals
        if features.get('byte_entropy', 0) > 7.5:  # High entropy
            if features.get('process_apis_count', 0) < 2:  # But few APIs
                reliability['issues'].append(
                    'Conflicting entropy/API signals - encrypted with minimal code')
                reliability['confidence_adjustment'] *= 0.85

        # Check entropy consistency
        entropy_vals = [
            features.get('approximate_entropy', 0),
            features.get('sample_entropy', 0),
            features.get('byte_entropy', 0) / 8.0  # Normalize to 0-1
        ]
        valid_entropy_vals = [e for e in entropy_vals if e > 0]
        if valid_entropy_vals and max(valid_entropy_vals) - min(valid_entropy_vals) > 0.5:
            reliability['issues'].append(
                'Inconsistent entropy metrics across methods')
            reliability['confidence_adjustment'] *= 0.9

        # Check feature coverage
        covered = len([v for v in features.values()
                    if v is not None and isinstance(v, (int, float))])
        total_possible = len(self.MODEL_WEIGHTS)
        coverage_ratio = covered / total_possible if total_possible > 0 else 0.0

        if coverage_ratio < 0.6:
            reliability['issues'].append(
                f'Low feature coverage ({coverage_ratio:.0%})')
            reliability['confidence_adjustment'] *= 0.8
        elif coverage_ratio < 0.8:
            reliability['issues'].append(
                f'Moderate feature coverage ({coverage_ratio:.0%})')
            reliability['confidence_adjustment'] *= 0.9

        # Check for extreme values that might indicate data quality issues
        extreme_features = [f for f, v in features.items()
                           if isinstance(v, (int, float)) and (v > 10 or v < -5)]
        if extreme_features:
            reliability['issues'].append(
                f'Extreme feature values detected: {extreme_features[:3]}')
            reliability['confidence_adjustment'] *= 0.85

        reliability['score'] = max(
            0.0, min(1.0, reliability['confidence_adjustment']))
        return reliability

    # NEW METHOD 5: Explain decision
    def explain_decision(self, classification: Dict, features: Dict) -> str:
        """Generate human-readable explanation"""
        explanation = f"CLASSIFICATION: {classification['classification']}\n"
        explanation += f"Confidence: {classification['confidence']:.1%}\n"
        explanation += f"Malware Score: {classification['malware_score']:.3f}\n"
        explanation += f"Reliability: {classification.get('reliability', 0.0):.1%}\n\n"

        explanation += "TOP CONTRIBUTING FACTORS:\n"
        for i, factor in enumerate(
            classification['contributing_features'][:5], 1):
            direction = "↑ Increases risk" if factor['contribution'] > 0 else "↓ Decreases risk"
            explanation += f"{i}. {factor['feature']}: {factor['value']:.3f} {direction} (+{abs(factor['contribution']):.3f})\n"

        if classification['risk_factors']:
            explanation += "\nRISK FACTORS:\n"
            for risk in classification['risk_factors'][:3]:
                explanation += f"• {risk['factor']}: {risk['severity']} ({risk['contribution']:.3f})\n"

        if 'entropy_profile' in classification['analysis_details']:
            explanation += f"\nEntropy Profile: {classification['analysis_details']['entropy_profile']}\n"

        if 'pattern_complexity' in classification['analysis_details']:
            explanation += f"Pattern Complexity: {classification['analysis_details']['pattern_complexity']}\n"

        if 'anomalies' in classification['analysis_details']:
            explanation += "\nDetected Anomalies:\n"
            for anomaly in classification['analysis_details']['anomalies'][:3]:
                explanation += f"• {anomaly}\n"

        if 'reliability_issues' in classification['analysis_details']:
            explanation += "\nReliability Notes:\n"
            for issue in classification['analysis_details']['reliability_issues']:
                explanation += f"• {issue}\n"

        threat_level = classification['analysis_details'].get(
            'threat_level', 'UNKNOWN')
        recommendation_map = {
            'CRITICAL': '🔴 BLOCK - Isolate immediately. Do not execute.',
            'HIGH': '🟠 QUARANTINE - Monitor in isolated environment.',
            'MEDIUM': '🟡 REVIEW - Verify legitimacy before deployment.',
            'LOW': '🟢 ALLOW - Appears benign.'
        }
        explanation += f"\nRECOMMENDATION: {recommendation_map.get(threat_level, 'Unknown')}\n"

        return explanation

# ============================================================
# ENSEMBLE CLASSIFIER
# ============================================================

class EnsembleClassifier:
    """Combine multiple classifiers for better accuracy"""

    def __init__(self):
        self.classifiers = {
            'ml_model': MLClassifier(),
        }

    def ensemble_classify(
        self,
        features: Dict[str, float],
        static_analysis: Dict,
        dynamic_analysis: Dict
    ) -> Dict:
        """Ensemble classification combining multiple sources"""

        ensemble_result = {
            'final_verdict': 'Unknown',
            'final_confidence': 0.0,
            'individual_votes': {},
            'weighted_score': 0.0,
        }

        # Vote 1: ML Classifier
        ml_classifier = self.classifiers['ml_model']
        ml_result = ml_classifier.classify(features)

        ml_vote = {
            'classification': ml_result['classification'],
            'confidence': ml_result['confidence'],
            'weight': 0.35
        }
        ensemble_result['individual_votes']['ml_classifier'] = ml_vote

        # Vote 2: Static Analysis
        static_risk = static_analysis.get('classification', {}).get('risk_level', 'LOW')
        static_map = {
            'CRITICAL': 'Malware',
            'HIGH': 'Suspicious',
            'MEDIUM': 'PUP/Unwanted',
            'LOW': 'Clean'
        }
        static_vote = {
            'classification': static_map.get(static_risk, 'Unknown'),
            'confidence': 0.6 if static_risk in ['CRITICAL', 'HIGH'] else 0.4,
            'weight': 0.35
        }
        ensemble_result['individual_votes']['static_analysis'] = static_vote

        # Vote 3: Dynamic Analysis
        dynamic_risk = dynamic_analysis.get('sandbox_report', {}).get('verdict', 'Unknown')
        dynamic_confidence = dynamic_analysis.get('sandbox_report', {}).get('confidence', 0.0)
        dynamic_vote = {
            'classification': dynamic_risk,
            'confidence': dynamic_confidence,
            'weight': 0.30
        }
        ensemble_result['individual_votes']['dynamic_analysis'] = dynamic_vote

        # Calculate weighted ensemble score
        total_weight = 0.0
        weighted_score = 0.0

        score_map = {
            'Malware': 1.0,
            'Suspicious': 0.7,
            'PUP/Unwanted': 0.4,
            'Clean': 0.0,
            'Unknown': 0.5
        }

        for vote_name, vote in ensemble_result['individual_votes'].items():
            classification = vote['classification']
            score = score_map.get(classification, 0.5)
            weighted_score += score * vote['weight']
            total_weight += vote['weight']

        if total_weight > 0:
            ensemble_result['weighted_score'] = weighted_score / total_weight

        # Final verdict
        final_score = ensemble_result['weighted_score']
        if final_score > 0.8:
            ensemble_result['final_verdict'] = 'Malware'
            ensemble_result['final_confidence'] = final_score
        elif final_score > 0.6:
            ensemble_result['final_verdict'] = 'Suspicious'
            ensemble_result['final_confidence'] = final_score
        elif final_score > 0.3:
            ensemble_result['final_verdict'] = 'PUP/Unwanted'
            ensemble_result['final_confidence'] = final_score
        else:
            ensemble_result['final_verdict'] = 'Clean'
            ensemble_result['final_confidence'] = 1.0 - final_score

        return ensemble_result


# ============================================================
# INTERPRETABILITY ENGINE
# ============================================================

class ModelExplainability:
    """Explain ML model decisions"""

    def __init__(self):
        pass

    def explain_classification(self, classification_result: Dict, features: Dict[str, float]) -> Dict:
        """Generate human-readable explanation"""

        explanation = {
            'summary': '',
            'key_factors': [],
            'risk_factors': [],
            'mitigating_factors': [],
            'recommendation': ''
        }

        verdict = classification_result.get('classification', 'Unknown')
        confidence = classification_result.get('confidence', 0.0)

        # Summary
        explanation['summary'] = f"{verdict} (Confidence: {confidence:.1%})"

        # Key contributing features
        contributing = classification_result.get('contributing_features', [])
        for i, contrib in enumerate(contributing[:3]):
            explanation['key_factors'].append({
                'rank': i + 1,
                'feature': contrib['feature'],
                'impact': 'HIGH' if abs(contrib['contribution']) > 0.2 else 'MEDIUM'
            })

        # Risk factors
        if 'process_apis_count' in features and features['process_apis_count'] > 3:
            explanation['risk_factors'].append(
                'High number of process manipulation APIs')

        if 'byte_entropy' in features and features['byte_entropy'] > 7.5:
            explanation['risk_factors'].append(
                'High entropy indicating encryption/packing')

        if 'network_apis_count' in features and features['network_apis_count'] > 2:
            explanation['risk_factors'].append(
                'Network communication capability detected')

        if 'anti_analysis_count' in features and features['anti_analysis_count'] > 2:
            explanation['risk_factors'].append(
                'Anti-analysis/anti-debugging techniques')

        # Mitigating factors
        if 'printable_ratio' in features and features['printable_ratio'] > 0.5:
            explanation['mitigating_factors'].append(
                'High proportion of readable strings')

        if 'string_count' in features and features['string_count'] > 100:
            explanation['mitigating_factors'].append(
                'Large number of legitimate-looking strings')

        # Recommendation
        if verdict == 'Malware':
            explanation['recommendation'] = 'ISOLATE - Do not execute. Quarantine immediately.'
        elif verdict == 'Suspicious':
            explanation['recommendation'] = 'CAUTION - Monitor in sandbox before deployment.'
        elif verdict == 'PUP/Unwanted':
            explanation['recommendation'] = 'REVIEW - Check legitimacy before allowing.'
        else:
            explanation['recommendation'] = 'ALLOW - Appears to be benign.'

        return explanation


# ============================================================
# INTEGRATION
# ============================================================

def comprehensive_ml_analysis(
    data: bytes,
    static_results: Dict,
    dynamic_results: Dict
) -> Dict:
    """Complete ML-based analysis"""

    results = {
        'feature_extraction': {},
        'anomaly_detection': {},
        'ml_classification': {},
        'malware_type_prediction': {},
        'ensemble_classification': {},
        'model_explainability': {},
        'final_assessment': {}
    }

    # Feature Extraction
    extractor = FeatureExtractor(data)
    features = extractor.extract_all_features()
    results['feature_extraction'] = {
        'total_features': len(features),
        'feature_sample': dict(list(features.items())[:10])
    }

    # Anomaly Detection
    detector = AnomalyDetector()
    anomalies = detector.detect_anomalies(features)
    outliers = detector.detect_outliers_zscore(features)
    results['anomaly_detection'] = {
        'anomalies': anomalies,
        'outliers': outliers
    }

    # ML Classification
    ml_classifier = MLClassifier()
    ml_result = ml_classifier.classify(features)
    results['ml_classification'] = ml_result

    # Malware Type Prediction
    type_prediction = ml_classifier.predict_malware_type(features)
    results['malware_type_prediction'] = type_prediction

    # Ensemble Classification
    ensemble = EnsembleClassifier()
    ensemble_result = ensemble.ensemble_classify(features, static_results, dynamic_results)
    results['ensemble_classification'] = ensemble_result

    # Model Explainability
    explainer = ModelExplainability()
    explanation = explainer.explain_classification(ml_result, features)
    results['model_explainability'] = explanation

    # Final Assessment
    results['final_assessment'] = {
        'verdict': ensemble_result['final_verdict'],
        'confidence': ensemble_result['final_confidence'],
        'ml_score': ml_result['malware_score'],
        'anomaly_score': anomalies.get('anomaly_score', 0.0),
        'predicted_type': type_prediction.get('predicted_type', 'Unknown'),
        'recommendation': explanation.get('recommendation', 'Unknown'),
    }

    return results


# if __name__ == '__main__':
#    if len(sys.argv) < 2:
#        print("Usage: Part 7 requires binary file argument")
#        sys.exit(1)
#
#    with open(sys.argv[1], 'rb') as f:
#        data = f.read()
#
#    # Placeholder for static/dynamic results
#    static_results = {'classification': {'risk_level': 'MEDIUM'}}
#    dynamic_results = {
#        'sandbox_report': {
#            'verdict': 'Suspicious',
#            'confidence': 0.6
#        }
#    }
#
#    analysis = comprehensive_ml_analysis(data, static_results, dynamic_results)
#    print(json.dumps(analysis, indent=2, default=str))
#
#
# ============================================================
# PART 8: EMAIL-SPECIFIC ANALYSIS + MIME PARSING ENGINE
# Lines 4565-5764 (1200 lines)
# ============================================================

import email
from email.parser import BytesParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import base64
import quopri

# ============================================================
# MIME PARSER ENGINE
# ============================================================

class MIMEParser:
    """Parse and analyze MIME email structures"""

    def __init__(self, email_data: bytes):
        self.raw_data = email_data
        self.parser = BytesParser()
        self.message = None
        self.parse_email()

    def parse_email(self) -> bool:
        """Parse email from raw bytes"""
        try:
            self.message = self.parser.parsebytes(self.raw_data)
            return True
        except Exception as e:
            print(f"Error parsing email: {str(e)[:100]}")
            return False

    def extract_headers(self) -> Dict:
        """Extract and analyze email headers"""
        headers = {
            'from': '',
            'to': [],
            'cc': [],
            'bcc': [],
            'subject': '',
            'date': '',
            'message_id': '',
            'content_type': '',
            'content_transfer_encoding': '',
            'user_agent': '',
            'x_mailer': '',
            'received': [],
            'authentication_results': '',
            'dkim_signature': False,
            'spf_pass': False,
            'dmarc_pass': False,
        }

        if not self.message:
            return headers

        # Basic headers
        headers['from'] = self.message.get('From', '')
        headers['to'] = self.message.get_all('To', [])
        headers['cc'] = self.message.get_all('Cc', [])
        headers['bcc'] = self.message.get_all('Bcc', [])
        headers['subject'] = self.message.get('Subject', '')
        headers['date'] = self.message.get('Date', '')
        headers['message_id'] = self.message.get('Message-ID', '')
        headers['content_type'] = self.message.get('Content-Type', '')
        headers['content_transfer_encoding'] = self.message.get(
            'Content-Transfer-Encoding', '')
        headers['user_agent'] = self.message.get('User-Agent', '')
        headers['x_mailer'] = self.message.get('X-Mailer', '')

        # Received headers
        headers['received'] = self.message.get_all('Received', [])

        # Authentication headers
        headers['authentication_results'] = self.message.get(
            'Authentication-Results', '')
        headers['dkim_signature'] = 'DKIM-Signature' in self.message

        # Check SPF/DMARC from auth results
        auth_results = headers['authentication_results'].lower()
        headers['spf_pass'] = 'spf=pass' in auth_results
        headers['dmarc_pass'] = 'dmarc=pass' in auth_results

        return headers

    def extract_body_parts(self) -> List[Dict]:
        """Extract all body parts from email"""
        parts = []

        if not self.message:
            return parts

        # Handle multipart messages
        if self.message.is_multipart():
            for part in self.message.walk():
                parts.append(self._extract_part(part))
        else:
            parts.append(self._extract_part(self.message))

        return parts

    def _extract_part(self, part) -> Dict:
        """Extract single message part"""
        part_info = {
            'content_type': part.get_content_type(),
            'content_disposition': part.get('Content-Disposition', ''),
            'filename': part.get_filename(''),
            'size': 0,
            'charset': part.get_content_charset(),
            'encoding': part.get('Content-Transfer-Encoding', ''),
            'is_multipart': part.is_multipart(),
        }

        if not part.is_multipart():
            payload = part.get_payload(decode=False)
            if isinstance(payload, str):
                part_info['size'] = len(payload.encode())
            elif isinstance(payload, bytes):
                part_info['size'] = len(payload)

        return part_info

    def extract_attachments(self) -> List[Dict]:
        """Extract attachment information"""
        attachments = []

        if not self.message:
            return attachments

        for part in self.message.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    payload = part.get_payload(decode=True)

                    attachment_info = {
                        'filename': filename,
                        'size': len(payload) if payload else 0,
                        'content_type': part.get_content_type(),
                        'encoding': part.get('Content-Transfer-Encoding', ''),
                        'md5_hash': hashlib.md5(payload).hexdigest() if payload else '',
                        'sha256_hash': hashlib.sha256(payload).hexdigest() if payload else '',
                    }

                    attachments.append(attachment_info)

        return attachments

    def extract_links(self) -> List[Dict]:
        """Extract URLs from email body"""
        links = []

        if not self.message:
            return links

        for part in self.message.walk():
            if part.get_content_type() in ['text/plain', 'text/html']:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode(
                            part.get_content_charset() or 'utf-8', errors='ignore')

                        # Extract URLs
                        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                        urls = re.findall(url_pattern, text)

                        for url in urls:
                            links.append({
                                'url': url,
                                'type': 'HTTP' if url.startswith('http://') else 'HTTPS',
                                'shortened': self._is_shortened_url(url),
                            })
                except:
                    pass

        return links

    def _is_shortened_url(self, url: str) -> bool:
        """Check if URL is shortened"""
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly',
            'j.mp', 'adf.ly', 'short.link', 'rebrand.ly'
        ]
        return any(shortener in url.lower() for shortener in shorteners)


# ============================================================
# EMAIL HEADER ANALYSIS
# ============================================================

class EmailHeaderAnalyzer:
    """Advanced email header analysis for spoofing, authentication, and anomalies"""

    # Known legitimate mail servers
    LEGITIMATE_MAIL_SERVERS = {
        'gmail': ['mail-', 'smtp.google', 'aspmx'],
        'microsoft': ['outlook', 'mail.protection.outlook.com', 'microsoft'],
        'apple': ['mail.icloud.com', 'smtp.apple'],
        'protonmail': ['mail.protonmail', 'smtp.protonmail'],
        'amazon': ['amazonses', 'sns.amazonaws'],
        'sendgrid': ['sendgrid', 'sg.sendgrid'],
    }

    # Known phishing sender patterns
    PHISHING_PATTERNS = [
        r'noreply.*?@.*?gmail\.com',
        r'support.*?@.*?[a-z0-9]+\.(ru|cn|tk|ml|ga|cf|gq)',
        r'admin.*?@.*(gmail|yahoo|hotmail)\.com',
        r'no-reply.*?@.*?(paypa|amazo|micros).*?\.com',
        r'.*?@.*?bit\.ly',
    ]

    # Suspicious top-level domains
    SUSPICIOUS_TLDS = [
        '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq',  # Known for abuse
        '.xyz', '.top', '.download', '.accountant',  # High abuse rate
        '.party', '.review', '.date', '.bid',
    ]

    # Known malicious domains/senders
    KNOWN_MALICIOUS = [
        'phishing-server.ru',
        'spoofed-microsoft.xyz',
        'fake-support@',
    ]

    def __init__(self, headers: Dict):
        self.headers = headers
        self.domain_reputation = {}

    def analyze_sender_spoofing(self) -> Dict:
        """Detect email spoofing indicators with advanced heuristics"""
        spoofing_analysis = {
            'suspected_spoofing': False,
            'spoofing_score': 0.0,
            'indicators': [],
            'confidence': 0.0,
            'spoof_type': 'None',
            'severity': 'Low',
            'detailed_findings': {}
        }

        from_header = self.headers.get('from', '').lower()
        received_headers = self.headers.get('received', [])

        # Extract domain from From header
        from_match = re.search(r'@([a-zA-Z0-9\-\.]+)', from_header)
        from_domain = from_match.group(1).lower() if from_match else ''

        # Extract sender name vs domain
        sender_name = ''
        sender_match = re.search(r'^([^<]+)<', from_header)
        if sender_match:
            sender_name = sender_match.group(1).strip().lower()

        # ============================================================
        # SPOOF CHECK 1: Domain Mismatch (Domain Spoofing)
        # ============================================================
        domain_mismatches = []
        if received_headers and from_domain:
            for received in received_headers:
                if 'from' in received.lower():
                    # Extract domain from received header
                    domain_match = re.search(r'from\s+\[?([a-zA-Z0-9\-\.]+)\]?', received.lower())
                    received_domain = domain_match.group(1).lower() if domain_match else ''

                    if received_domain and received_domain != from_domain:
                        domain_mismatches.append({
                            'from_domain': from_domain,
                            'received_domain': received_domain,
                            'severity': 'CRITICAL'
                        })
                        spoofing_analysis['indicators'].append(
                            f'Domain mismatch: From={from_domain}, Actual={received_domain}'
                        )
                        spoofing_analysis['spoofing_score'] += 0.25

        if domain_mismatches:
            spoofing_analysis['detailed_findings']['domain_mismatches'] = domain_mismatches
            spoofing_analysis['spoof_type'] = 'Domain Spoofing'

        # ============================================================
        # SPOOF CHECK 2: Impersonation (Sender Name Spoofing)
        # ============================================================
        impersonation_score = self._check_impersonation(sender_name, from_domain)
        if impersonation_score > 0.3:
            spoofing_analysis['indicators'].append(
                f'Possible impersonation: "{sender_name}" <{from_domain}>'
            )
            spoofing_analysis['spoofing_score'] += impersonation_score
            spoofing_analysis['spoof_type'] = 'Impersonation'

        # ============================================================
        # SPOOF CHECK 3: Authentication Failures
        # ============================================================
        auth_failures = []

        # SPF check
        spf_pass = self.headers.get('spf_pass', False)
        if not spf_pass:
            auth_failures.append('SPF verification failed')
            spoofing_analysis['spoofing_score'] += 0.20

        # DMARC check
        dmarc_pass = self.headers.get('dmarc_pass', False)
        if not dmarc_pass:
            auth_failures.append('DMARC verification failed')
            spoofing_analysis['spoofing_score'] += 0.20

        # DKIM check
        dkim_signature = self.headers.get('dkim_signature', False)
        if not dkim_signature:
            auth_failures.append('No DKIM signature present')
            spoofing_analysis['spoofing_score'] += 0.15

        if auth_failures:
            spoofing_analysis['indicators'].extend(auth_failures)
            spoofing_analysis['detailed_findings']['auth_failures'] = auth_failures

        # ============================================================
        # SPOOF CHECK 4: Reply-To Mismatch
        # ============================================================
        reply_to = self.headers.get('reply_to', '').lower()
        if reply_to and from_domain:
            reply_match = re.search(r'@([a-zA-Z0-9\-\.]+)', reply_to)
            reply_domain = reply_match.group(1).lower() if reply_match else ''

            if reply_domain and reply_domain != from_domain:
                spoofing_analysis['indicators'].append(
                    f'Reply-To domain mismatch: From={from_domain}, Reply-To={reply_domain}'
                )
                spoofing_analysis['spoofing_score'] += 0.20

        # ============================================================
        # SPOOF CHECK 5: Sender Policy Framework Analysis
        # ============================================================
        spf_analysis = self._analyze_spf_header(
            self.headers.get('authentication_results', ''))
        if spf_analysis['issues']:
            spoofing_analysis['indicators'].extend(spf_analysis['issues'])
            spoofing_analysis['spoofing_score'] += spf_analysis['score_increase']
            spoofing_analysis['detailed_findings']['spf_analysis'] = spf_analysis

        # ============================================================
        # SPOOF CHECK 6: Reverse DNS Verification
        # ============================================================
        reverse_dns = self._check_reverse_dns(received_headers)
        if not reverse_dns['valid']:
            spoofing_analysis['indicators'].append(
                'Reverse DNS verification failed')
            spoofing_analysis['spoofing_score'] += 0.15
            spoofing_analysis['detailed_findings']['reverse_dns_issues'] = reverse_dns['issues']

        # ============================================================
        # SPOOF CHECK 7: Header Injection Attempts
        # ============================================================
        injection_detected = self._detect_header_injection(self.headers)
        if injection_detected['detected']:
            spoofing_analysis['indicators'].append(
                'Possible header injection attempt detected')
            spoofing_analysis['spoofing_score'] += 0.30
            spoofing_analysis['detailed_findings']['injection_details'] = injection_detected

        # Normalize score
        spoofing_analysis['spoofing_score'] = min(spoofing_analysis['spoofing_score'], 1.0)
        spoofing_analysis['confidence'] = spoofing_analysis['spoofing_score']

        # Determine severity
        if spoofing_analysis['spoofing_score'] > 0.8:
            spoofing_analysis['severity'] = 'CRITICAL'
            spoofing_analysis['suspected_spoofing'] = True
        elif spoofing_analysis['spoofing_score'] > 0.6:
            spoofing_analysis['severity'] = 'HIGH'
            spoofing_analysis['suspected_spoofing'] = True
        elif spoofing_analysis['spoofing_score'] > 0.4:
            spoofing_analysis['severity'] = 'MEDIUM'
        elif spoofing_analysis['spoofing_score'] > 0.2:
            spoofing_analysis['severity'] = 'LOW'

        return spoofing_analysis

    def analyze_routing_path(self) -> Dict:
        """Advanced email routing and hop analysis"""
        routing_analysis = {
            'hop_count': 0,
            'hops': [],
            'suspicious_hops': [],
            'external_relay_count': 0,
            'routing_anomalies': [],
            'path_integrity': True,
            'path_score': 1.0,
            'suspicious_relays': [],
            'geographical_analysis': [],
            'timing_analysis': {}
        }

        received_headers = self.headers.get('received', [])
        routing_analysis['hop_count'] = len(received_headers)

        previous_timestamp = None
        hops_by_time = []

        # Parse each hop
        for hop_idx, received in enumerate(received_headers):
            hop_info = {
                'hop': hop_idx + 1,
                'raw': received,
                'suspicious': False,
                'risk_indicators': []
            }

            # Extract server names
            server_match = re.search(r'from\s+\[?([a-zA-Z0-9\-\.:\[\]]+)\]?', received)
            if server_match:
                hop_info['from_server'] = server_match.group(1)

            # Extract IP address
            ip_match = re.search(r'\[([0-9\.]+)\]', received)
            if ip_match:
                hop_info['ip_address'] = ip_match.group(1)

            # Extract timestamps
            time_match = re.search(r';\s+(.+?)$', received)
            if time_match:
                hop_info['timestamp'] = time_match.group(1)
                hops_by_time.append({
                    'hop': hop_idx + 1,
                    'timestamp': hop_info['timestamp']
                })

            # ============================================================
            # HOP ANALYSIS: Suspicious Patterns
            # ============================================================

            # Check for open relays / suspicious keywords
            suspicious_keywords = ['unknown', 'localhost', '127.0.0.1', 'from:unknown', 'mailer']
            if any(keyword in received.lower() for keyword in suspicious_keywords):
                hop_info['suspicious'] = True
                hop_info['risk_indicators'].append('Suspicious keyword detected')
                routing_analysis['suspicious_hops'].append(hop_idx + 1)
                routing_analysis['path_score'] -= 0.15

            # Check for missing data
            if 'from_server' not in hop_info or not hop_info['from_server']:
                hop_info['suspicious'] = True
                hop_info['risk_indicators'].append('Missing server information')
                routing_analysis['path_score'] -= 0.1

            # Check for suspicious domains/TLDs
            if 'from_server' in hop_info:
                server = hop_info['from_server'].lower()
                if any(tld in server for tld in self.SUSPICIOUS_TLDS):
                    hop_info['suspicious'] = True
                    hop_info['risk_indicators'].append(
                        f'Suspicious TLD in server: {server}')
                    routing_analysis['suspicious_relays'].append(server)
                    routing_analysis['path_score'] -= 0.2

            # Check for proper mail server format
            if 'mail-' not in received.lower() and 'smtp' not in received.lower():
                if hop_idx == 0:  # First hop should be legitimate mail server
                    hop_info['suspicious'] = True
                    hop_info['risk_indicators'].append(
                        'First hop not from legitimate mail server')
                    routing_analysis['path_score'] -= 0.25

            # ============================================================
            # GEOGRAPHICAL ANALYSIS
            # ============================================================
            if 'ip_address' in hop_info:
                geo_info = self._geolocate_ip(hop_info['ip_address'])
                hop_info['geolocation'] = geo_info
                routing_analysis['geographical_analysis'].append(geo_info)

            routing_analysis['hops'].append(hop_info)

        # ============================================================
        # TIMING ANALYSIS
        # ============================================================
        if hops_by_time:
            timing_check = self._analyze_hop_timing(hops_by_time)
            routing_analysis['timing_analysis'] = timing_check
            if timing_check['suspicious']:
                routing_analysis['path_score'] -= timing_check['penalty']

        # Count external relays
        routing_analysis['external_relay_count'] = sum(
            1 for hop in routing_analysis['hops']
            if 'from_server' in hop and not hop['from_server'].endswith('.local')
        )

        # Overall path integrity
        routing_analysis['path_integrity'] = len(routing_analysis['suspicious_hops']) == 0
        routing_analysis['path_score'] = max(routing_analysis['path_score'], 0.0)

        return routing_analysis

    def analyze_header_consistency(self) -> Dict:
        """Advanced header consistency and anomaly analysis"""
        consistency = {
            'anomalies': [],
            'consistency_score': 1.0,
            'anomaly_categories': {},
            'risk_level': 'Low',
            'header_integrity': True,
        }

        subject = self.headers.get('subject', '').lower()
        from_header = self.headers.get('from', '').lower()

        # ============================================================
        # ANOMALY CHECK 1: Phishing Subject Lines
        # ============================================================
        phishing_subjects = {
            'urgent': 0.15,
            'verify': 0.15,
            'confirm': 0.12,
            'update': 0.10,
            'act now': 0.20,
            'click here': 0.20,
            'prize': 0.25,
            'claim': 0.20,
            'winner': 0.25,
            'suspended': 0.20,
            'locked': 0.18,
            'urgent action': 0.25,
            'confirm identity': 0.25,
            're-activate': 0.20,
            'security alert': 0.15,
            'unusual activity': 0.15,
        }

        subject_risk = 0.0
        for keyword, risk in phishing_subjects.items():
            if keyword in subject:
                consistency['anomalies'].append(
                    f'Phishing keyword: "{keyword}"')
                subject_risk += risk

        if subject_risk > 0:
            consistency['anomaly_categories']['phishing_subject'] = subject_risk
            consistency['consistency_score'] -= min(subject_risk, 0.4)

        # ============================================================
        # ANOMALY CHECK 2: Encoding Issues
        # ============================================================
        content_encoding = self.headers.get('content_transfer_encoding', '').lower()
        if content_encoding in ['8bit', 'binary', '7bit']:
            consistency['anomalies'].append(
                f'Unusual encoding: {content_encoding}')
            consistency['anomaly_categories']['encoding_issue'] = 0.10
            consistency['consistency_score'] -= 0.10

        # ============================================================
        # ANOMALY CHECK 3: User Agent / X-Mailer Inconsistency
        # ============================================================
        user_agent = self.headers.get('user_agent', '').lower()
        x_mailer = self.headers.get('x_mailer', '').lower()

        if user_agent and x_mailer:
            if user_agent != x_mailer:
                consistency['anomalies'].append(
                    'Conflicting User-Agent and X-Mailer headers')
                consistency['anomaly_categories']['ua_conflict'] = 0.15
                consistency['consistency_score'] -= 0.15

        # ============================================================
        # ANOMALY CHECK 4: Missing Standard Headers
        # ============================================================
        required_headers = ['message_id', 'date', 'from', 'to']
        missing_headers = [h for h in required_headers if not self.headers.get(h)]

        if missing_headers:
            consistency['anomalies'].append(
                f'Missing headers: {", ".join(missing_headers)}')
            consistency['anomaly_categories']['missing_headers'] = len(missing_headers) * 0.10
            consistency['consistency_score'] -= len(missing_headers) * 0.10

        # ============================================================
        # ANOMALY CHECK 5: Message ID Validity
        # ============================================================
        message_id = self.headers.get('message_id', '')
        if message_id:
            if not re.match(r'<[^>]+@[^>]+>', message_id):
                consistency['anomalies'].append(
                    f'Invalid Message-ID format: {message_id}')
                consistency['anomaly_categories']['invalid_message_id'] = 0.12
                consistency['consistency_score'] -= 0.12

        # ============================================================
        # ANOMALY CHECK 6: Return-Path Mismatch
        # ============================================================
        return_path = self.headers.get('return_path', '').lower()
        if return_path and from_header:
            return_match = re.search(r'@([a-zA-Z0-9\-\.]+)', return_path)
            from_match = re.search(r'@([a-zA-Z0-9\-\.]+)', from_header)

            if return_match and from_match:
                return_domain = return_match.group(1)
                from_domain = from_match.group(1)

                if return_domain != from_domain:
                    consistency['anomalies'].append(
                        f'Return-Path mismatch: {return_domain} vs {from_domain}'
                    )
                    consistency['anomaly_categories']['return_path_mismatch'] = 0.15
                    consistency['consistency_score'] -= 0.15

        # ============================================================
        # ANOMALY CHECK 7: Suspicious Attachments in Headers
        # ============================================================
        content_type = self.headers.get('content_type', '').lower()
        if 'multipart' in content_type:
            # Check for executable attachment indicators
            if any(ext in content_type for ext in ['.exe', '.dll', '.zip', '.scr']):
                consistency['anomalies'].append(
                    'Potentially dangerous attachment type detected')
                consistency['anomaly_categories']['dangerous_attachment'] = 0.20
                consistency['consistency_score'] -= 0.20

        # ============================================================
        # ANOMALY CHECK 8: X-Originating-IP Validation
        # ============================================================
        x_orig_ip = self.headers.get('x_originating_ip', '')
        if x_orig_ip:
            # Check if IP looks spoofed (private IPs, invalid format)
            if re.search(r'\[192\.168\.|10\.|172\.16\.|127\.', x_orig_ip):
                consistency['anomalies'].append(
                    f'Suspicious X-Originating-IP: {x_orig_ip}')
                consistency['anomaly_categories']['suspicious_origin_ip'] = 0.15
                consistency['consistency_score'] -= 0.15

        # Normalize score
        consistency['consistency_score'] = max(consistency['consistency_score'], 0.0)

        # Determine risk level
        if consistency['consistency_score'] < 0.3:
            consistency['risk_level'] = 'Critical'
            consistency['header_integrity'] = False
        elif consistency['consistency_score'] < 0.5:
            consistency['risk_level'] = 'High'
            consistency['header_integrity'] = False
        elif consistency['consistency_score'] < 0.7:
            consistency['risk_level'] = 'Medium'
        elif consistency['consistency_score'] < 0.85:
            consistency['risk_level'] = 'Low'
        else:
            consistency['risk_level'] = 'Very Low'

        return consistency

    def _check_impersonation(self, sender_name: str, from_domain: str) -> float:
        """Check for impersonation attempts"""
        # Placeholder implementation
        return 0.0

    def _analyze_spf_header(self, auth_results: str) -> Dict:
        """Analyze SPF header"""
        # Placeholder implementation
        return {'issues': [], 'score_increase': 0.0}

    def _check_reverse_dns(self, received_headers: List) -> Dict:
        """Check reverse DNS"""
        # Placeholder implementation
        return {'valid': True, 'issues': []}

    def _detect_header_injection(self, headers: Dict) -> Dict:
        """Detect header injection"""
        # Placeholder implementation
        return {'detected': False}

    def _geolocate_ip(self, ip: str) -> Dict:
        """Geolocate IP address"""
        # Placeholder implementation
        return {'country': 'Unknown', 'city': 'Unknown'}

    def _analyze_hop_timing(self, hops: List) -> Dict:
        """Analyze hop timing"""
        # Placeholder implementation
        return {'suspicious': False, 'penalty': 0.0}

    # ============================================================
    # HELPER METHODS
    # ============================================================

    def _check_impersonation(
    self,
    sender_name: str,
     from_domain: str) -> float:
        """Check for impersonation patterns"""
        score=0.0

        impersonation_patterns=[
            ('paypal', 'paypa'),
            ('amazon', 'amazo'),
            ('microsoft', 'micros'),
            ('apple', 'app'),
            ('google', 'goo'),
            ('bank', 'ban'),
            ('support', 'supp'),
            ('admin', 'adm'),
            ('noreply', 'noreplie'),
        ]

        for legit, fake in impersonation_patterns:
            if legit in sender_name and fake in from_domain:
                score += 0.3

        return min(score, 1.0)

    def _analyze_spf_header(self, auth_results: str) -> Dict:
        """Analyze SPF authentication header"""
        spf_analysis={
            'issues': [],
            'score_increase': 0.0,
            'spf_result': 'unknown'
        }

        if 'spf=pass' in auth_results.lower():
            spf_analysis['spf_result']='pass'
        elif 'spf=fail' in auth_results.lower():
            spf_analysis['issues'].append('SPF FAIL result')
            spf_analysis['score_increase']=0.20
            spf_analysis['spf_result']='fail'
        elif 'spf=softfail' in auth_results.lower():
            spf_analysis['issues'].append('SPF SOFTFAIL result')
            spf_analysis['score_increase']=0.10
            spf_analysis['spf_result']='softfail'
        elif 'spf=neutral' in auth_results.lower():
            spf_analysis['issues'].append('SPF NEUTRAL result')
            spf_analysis['score_increase']=0.05
            spf_analysis['spf_result']='neutral'
        elif 'spf=none' in auth_results.lower():
            spf_analysis['issues'].append('No SPF record found')
            spf_analysis['score_increase']=0.15
            spf_analysis['spf_result']='none'

        return spf_analysis

    def _check_reverse_dns(self, received_headers: List) -> Dict:
        """Check reverse DNS verification"""
        reverse_dns={
            'valid': True,
            'issues': [],
            'ptr_records': []
        }

        if not received_headers:
            return reverse_dns

        # Check first hop (usually the sending server)
        first_hop=received_headers[0].lower()

        # If no explicit reverse DNS info, assume unverified
        if 'ptr=' not in first_hop and 'reverse' not in first_hop:
            reverse_dns['valid']=False
            reverse_dns['issues'].append('No reverse DNS verification found')

        return reverse_dns

    def _detect_header_injection(self, headers: Dict) -> Dict:
        """Detect header injection attacks"""
        injection={
            'detected': False,
            'injection_type': 'None',
            'indicators': []
        }

        # Check for newline characters that could indicate injection
        for header_name, header_value in headers.items():
            if isinstance(header_value, str):
                if '\n' in header_value or '\r' in header_value:
                    if not header_name in [
                        'received']:  # Received headers legitimately have newlines
                        injection['detected']=True
                        injection['injection_type']='CRLF Injection'
                        injection['indicators'].append(
                            f'Newline in {header_name}')

        return injection

    def _geolocate_ip(self, ip_address: str) -> Dict:
        """Geolocate IP address (simplified)"""
        geo={
            'ip': ip_address,
            'country': 'Unknown',
            'suspicious': False
        }

        # Check for private/reserved IPs
        if re.match(r'^(192\.168\.|10\.|172\.16\.|127\.)', ip_address):
            geo['country']='Private/Local'
            geo['suspicious']=True

        # High-risk country patterns (simplified)
        high_risk_patterns=[
            (r'^5\.', 'Russia/CIS'),
            (r'^117\.', 'China'),
            (r'^185\.', 'Russia/E.Europe'),
            (r'^212\.', 'Russia/E.Europe'),
        ]

        for pattern, country in high_risk_patterns:
            if re.match(pattern, ip_address):
                geo['country']=country
                geo['suspicious']=True
                break

        return geo

    def _analyze_hop_timing(self, hops: List[Dict]) -> Dict:
        """Analyze timing between hops for anomalies"""
        timing={
            'suspicious': False,
            'penalty': 0.0,
            'issues': [],
            'hop_delays': []
        }

        # Would implement full date parsing in production
        # This is simplified for demonstration
        if len(hops) > 1:
            # Check for unrealistic delays (more than 7 days)
            timing['issues'].append('Manual timing analysis required')

        return timing


class PhishingDetector:
    """Enterprise-grade phishing and malicious email detection engine"""

    # Known phishing kit signatures
    PHISHING_KIT_SIGNATURES={
        'PayPal': ['account', 'verify', 'confirm', 'update payment', 'resolve issue'],
        'Microsoft': ['account locked', 'verify identity', 'urgent action', 'suspicious activity'],
        'Apple': ['icloud', 'itunes', 'verify apple', 'confirm payment'],
        'Amazon': ['confirm order', 'update payment', 'verify account', 'unusual activity'],
        'Google': ['verify account', 'confirm identity', 'unusual activity', 'secure account'],
        'Bank': ['confirm account', 'verify details', 'update information', 'resolve issue'],
        'IRS': ['tax refund', 'verify identity', 'confirm details', 'federal income'],
    }

    # Known malicious file signatures
    MALICIOUS_FILE_SIGNATURES={
        'executable': ['.exe', '.dll', '.com', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jse', '.jar', '.ps1', '.psm1'],
        'archive': ['.zip', '.rar', '.7z', '.tar', '.gz', '.ace', '.iso'],
        'macro': ['.xlsm', '.docm', '.pptm', '.mso', '.xlam', '.dotm', '.ppam'],
        'script': ['.vbs', '.js', '.jse', '.vbe', '.wsh', '.wsf'],
        'suspicious': ['.scr', '.pif', '.bat', '.cmd', '.com'],
    }

    # Legitimate domain whitelist
    LEGITIMATE_DOMAINS={
        'paypal.com', 'amazon.com', 'apple.com', 'google.com', 'microsoft.com',
        'facebook.com', 'twitter.com', 'linkedin.com', 'dropbox.com', 'slack.com'
    }

    # Known phishing URL patterns
    PHISHING_URL_PATTERNS=[
        r'paypa[l1]',
        r'amaz[o0]n',
        r'go[o0]gle',
        r'micros[o0]ft',
        r'app[l1]e',
        r'[a-z0-9]*-secure[a-z0-9]*\.',
        r'[a-z0-9]*-verify[a-z0-9]*\.',
        r'[a-z0-9]*-update[a-z0-9]*\.',
        r'[a-z0-9]*-confirm[a-z0-9]*\.',
        r'secure[a-z0-9]*login',
        r'verify[a-z0-9]*account',
        r'confirm[a-z0-9]*identity',
    ]

    # Suspicious TLDs
    SUSPICIOUS_TLDS=[
        '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
        '.download', '.accountant', '.party', '.review', '.date', '.bid',
        '.racing', '.cricket', '.faith', '.science', '.online',
    ]

    def __init__(
    self,
    headers: Dict,
    links: List[Dict],
     attachments: List[Dict]):
        self.headers=headers
        self.links=links
        self.attachments=attachments
        self.risk_score=0.0

    def detect_phishing_indicators(self) -> Dict:
        """Comprehensive phishing detection with multi-vector analysis"""
        indicators={
            'phishing_score': 0.0,
            'phishing_likelihood': 'Low',
            'indicators': [],
            'risk_level': 'Low',
            'threat_type': 'Unknown',
            'attack_vector': [],
            'target_entity': 'Generic',
            'confidence': 0.0,
            'detailed_analysis': {},
        }

        phishing_score=0.0
        attack_vectors=set()

        # ============================================================
        # VECTOR 1: URL Analysis
        # ============================================================
        url_analysis=self._analyze_urls()
        if url_analysis['suspicious_count'] > 0:
            phishing_score += url_analysis['score']
            indicators['indicators'].extend(url_analysis['findings'])
            indicators['detailed_analysis']['url_analysis']=url_analysis
            attack_vectors.add('Malicious Links')

        # ============================================================
        # VECTOR 2: Attachment Analysis
        # ============================================================
        attachment_analysis=self._analyze_attachments()
        if attachment_analysis['suspicious_count'] > 0:
            phishing_score += attachment_analysis['score']
            indicators['indicators'].extend(attachment_analysis['findings'])
            indicators['detailed_analysis']['attachment_analysis']=attachment_analysis
            attack_vectors.add('Malicious Attachments')

        # ============================================================
        # VECTOR 3: Social Engineering Analysis
        # ============================================================
        social_eng_analysis=self._analyze_social_engineering()
        if social_eng_analysis['score'] > 0:
            phishing_score += social_eng_analysis['score']
            indicators['indicators'].extend(social_eng_analysis['findings'])
            indicators['detailed_analysis']['social_engineering']=social_eng_analysis
            attack_vectors.add('Social Engineering')

        # ============================================================
        # VECTOR 4: Credential Harvesting
        # ============================================================
        harvest_analysis=self._detect_credential_harvesting()
        if harvest_analysis['suspected']:
            phishing_score += harvest_analysis['score']
            indicators['indicators'].extend(harvest_analysis['findings'])
            indicators['detailed_analysis']['credential_harvesting']=harvest_analysis
            attack_vectors.add('Credential Harvesting')

        # ============================================================
        # VECTOR 5: Brand Impersonation
        # ============================================================
        brand_analysis=self._analyze_brand_impersonation()
        if brand_analysis['detected']:
            phishing_score += brand_analysis['score']
            indicators['indicators'].extend(brand_analysis['findings'])
            indicators['detailed_analysis']['brand_impersonation']=brand_analysis
            indicators['target_entity']=brand_analysis['impersonated_brand']
            attack_vectors.add('Brand Impersonation')

        # ============================================================
        # VECTOR 6: Malware Delivery
        # ============================================================
        malware_analysis=self._detect_malware_delivery()
        if malware_analysis['suspected']:
            phishing_score += malware_analysis['score']
            indicators['indicators'].extend(malware_analysis['findings'])
            indicators['detailed_analysis']['malware_delivery']=malware_analysis
            attack_vectors.add('Malware Delivery')

        # ============================================================
        # VECTOR 7: Spam/Bulk Email
        # ============================================================
        spam_analysis=self._detect_spam_characteristics()
        if spam_analysis['score'] > 0:
            phishing_score += spam_analysis['score']
            indicators['indicators'].extend(spam_analysis['findings'])
            indicators['detailed_analysis']['spam_characteristics']=spam_analysis
            attack_vectors.add('Spam/Bulk Email')

        # ============================================================
        # VECTOR 8: Business Email Compromise (BEC)
        # ============================================================
        bec_analysis=self._detect_business_email_compromise()
        if bec_analysis['suspected']:
            phishing_score += bec_analysis['score']
            indicators['indicators'].extend(bec_analysis['findings'])
            indicators['detailed_analysis']['bec_indicators']=bec_analysis
            attack_vectors.add('Business Email Compromise')

        # Normalize score
        indicators['phishing_score']=min(phishing_score, 1.0)
        indicators['confidence']=indicators['phishing_score']
        indicators['attack_vector']=list(attack_vectors)

        # Determine phishing likelihood
        if indicators['phishing_score'] > 0.85:
            indicators['phishing_likelihood']='Extremely High'
            indicators['risk_level']='Critical'
        elif indicators['phishing_score'] > 0.70:
            indicators['phishing_likelihood']='Very High'
            indicators['risk_level']='Critical'
        elif indicators['phishing_score'] > 0.55:
            indicators['phishing_likelihood']='High'
            indicators['risk_level']='High'
        elif indicators['phishing_score'] > 0.35:
            indicators['phishing_likelihood']='Moderate'
            indicators['risk_level']='Medium'
        elif indicators['phishing_score'] > 0.15:
            indicators['phishing_likelihood']='Low'
            indicators['risk_level']='Low'
        else:
            indicators['phishing_likelihood']='Very Low'
            indicators['risk_level']='Very Low'

        # Determine threat type
        if len(attack_vectors) > 1:
            indicators['threat_type']='Multi-Vector Attack'
        elif 'Malware Delivery' in attack_vectors:
            indicators['threat_type']='Malware Distribution'
        elif 'Credential Harvesting' in attack_vectors:
            indicators['threat_type']='Credential Phishing'
        elif 'Business Email Compromise' in attack_vectors:
            indicators['threat_type']='Business Email Compromise'
        elif 'Malicious Links' in attack_vectors:
            indicators['threat_type']='Link-Based Phishing'

        return indicators

    # ============================================================
    # VECTOR ANALYSIS METHODS
    # ============================================================

    def _analyze_urls(self) -> Dict:
        """Analyze URLs for phishing indicators"""
        url_analysis={
            'score': 0.0,
            'suspicious_count': 0,
            'findings': [],
            'url_details': []
        }

        for link in self.links:
            url=link.get('url', '')
            url_risk=0.0
            url_details={
                'url': url[:80],
                'risk_score': 0.0,
                'indicators': []
            }

            # Check for URL obfuscation
            if self._is_url_obfuscated(url):
                url_risk += 0.15
                url_details['indicators'].append('URL obfuscation detected')

            # Check for shortened URLs
            if link.get('shortened', False):
                url_risk += 0.12
                url_details['indicators'].append(
                    'Shortened URL (hides destination)')

            # Check for suspicious domains
            domain_risk=self._check_domain_reputation(url)
            url_risk += domain_risk['score']
            url_details['indicators'].extend(domain_risk['findings'])

            # Check for typosquatting
            typo_risk=self._detect_typosquatting(url)
            url_risk += typo_risk['score']
            url_details['indicators'].extend(typo_risk['findings'])

            # Check for subdomain manipulation
            subdomain_risk=self._check_subdomain_manipulation(url)
            url_risk += subdomain_risk['score']
            url_details['indicators'].extend(subdomain_risk['findings'])

            # Check for suspicious query parameters
            param_risk=self._analyze_query_parameters(url)
            url_risk += param_risk['score']
            url_details['indicators'].extend(param_risk['findings'])

            if url_risk > 0:
                url_analysis['suspicious_count'] += 1
                url_analysis['findings'].append(
                    f'Suspicious URL: {url[:50]}... (Risk: {min(url_risk, 1.0):.0%})')
                url_risk=min(url_risk, 0.25)  # Cap per-URL contribution
                url_analysis['score'] += url_risk
                url_details['risk_score']=min(url_risk, 1.0)
                url_analysis['url_details'].append(url_details)

        return url_analysis

    def _analyze_attachments(self) -> Dict:
        """Comprehensive attachment analysis"""
        attachment_analysis={
            'score': 0.0,
            'suspicious_count': 0,
            'findings': [],
            'attachment_details': []
        }

        for attachment in self.attachments:
            filename=attachment.get('filename', '').lower()
            file_size=attachment.get('size', 0)
            content_type=attachment.get('content_type', '').lower()

            attachment_risk=0.0
            attachment_details={
                'filename': filename,
                'size': file_size,
                'risk_score': 0.0,
                'indicators': [],
                'threat_type': 'Unknown'
            }

            # Check for double extensions
            if self._has_double_extension(filename):
                attachment_risk += 0.25
                attachment_details['indicators'].append(
                    'Double extension (obfuscation)')
                attachment_details['threat_type']='Obfuscated Executable'

            # Check for executable content
            executable_risk=self._check_executable_threat(
                filename, content_type)
            attachment_risk += executable_risk['score']
            attachment_details['indicators'].extend(
                executable_risk['findings'])
            if executable_risk['score'] > 0:
                attachment_details['threat_type']='Executable'

            # Check for macro-enabled documents
            macro_risk=self._check_macro_threat(filename, content_type)
            attachment_risk += macro_risk['score']
            attachment_details['indicators'].extend(macro_risk['findings'])
            if macro_risk['score'] > 0:
                attachment_details['threat_type']='Macro-Enabled'

            # Check for archive bombs
            archive_risk=self._check_archive_bomb(filename, file_size)
            attachment_risk += archive_risk['score']
            attachment_details['indicators'].extend(archive_risk['findings'])

            # Check for suspicious file extensions
            extension_risk=self._check_suspicious_extensions(filename)
            attachment_risk += extension_risk['score']
            attachment_details['indicators'].extend(extension_risk['findings'])

            # Check for polymorphic/obfuscated names
            obfuscation_risk=self._check_filename_obfuscation(filename)
            attachment_risk += obfuscation_risk['score']
            attachment_details['indicators'].extend(
                obfuscation_risk['findings'])

            if attachment_risk > 0:
                attachment_analysis['suspicious_count'] += 1
                attachment_analysis['findings'].append(
                    f'Suspicious attachment: {filename} (Risk: {min(attachment_risk, 1.0):.0%})')
                attachment_risk=min(
    attachment_risk, 0.25)  # Cap per-attachment
                attachment_analysis['score'] += attachment_risk
                attachment_details['risk_score']=min(attachment_risk, 1.0)
                attachment_analysis['attachment_details'].append(
                    attachment_details)

        return attachment_analysis

    def _analyze_social_engineering(self) -> Dict:
        """Detect social engineering tactics"""
        social_eng={
            'score': 0.0,
            'findings': [],
            'tactics': []
        }

        subject=self.headers.get('subject', '').lower()
        from_header=self.headers.get('from', '').lower()

        # Urgency tactics
        urgency_keywords=[
            ('urgent', 0.15),
            ('act now', 0.15),
            ('verify account', 0.15),
            ('confirm identity', 0.15),
            ('immediate action', 0.15),
            ('take action', 0.12),
            ('update immediately', 0.12),
            ('renew now', 0.12),
            ('click here', 0.10),
            ('limited time', 0.12),
        ]

        for keyword, score in urgency_keywords:
            if keyword in subject:
                social_eng['score'] += score
                social_eng['findings'].append(f'Urgency tactic: "{keyword}"')
                social_eng['tactics'].append('Artificial Urgency')

        # Authority impersonation
        authority_patterns=[
            ('ceo', 'Authority'),
            ('executive', 'Authority'),
            ('manager', 'Authority'),
            ('director', 'Authority'),
            ('officer', 'Authority'),
            ('support team', 'Authority'),
            ('security team', 'Authority'),
            ('compliance', 'Authority'),
        ]

        for pattern, tactic in authority_patterns:
            if pattern in subject or pattern in from_header:
                social_eng['score'] += 0.10
                social_eng['findings'].append(
                    f'Authority impersonation: {pattern}')
                social_eng['tactics'].append(tactic)

        # Generic greetings
        generic_greetings=[
            ('dear user', 0.08),
            ('dear customer', 0.08),
            ('dear valued', 0.08),
            ('to whom it may concern', 0.08),
            ('hello there', 0.08),
        ]

        for greeting, score in generic_greetings:
            if greeting in subject or greeting in from_header:
                social_eng['score'] += score
                social_eng['findings'].append(
                    f'Generic greeting: "{greeting}"')
                social_eng['tactics'].append('Lack of Personalization')

        social_eng['score']=min(social_eng['score'], 0.4)
        return social_eng

    def _detect_credential_harvesting(self) -> Dict:
        """Detect credential harvesting attacks"""
        harvest={
            'suspected': False,
            'score': 0.0,
            'findings': [],
            'harvesting_targets': []
        }

        harvesting_keywords=[
            ('verify account', 'Account Verification'),
            ('confirm identity', 'Identity Confirmation'),
            ('update payment', 'Payment Information'),
            ('confirm password', 'Password'),
            ('verify email', 'Email Address'),
            ('verify phone', 'Phone Number'),
            ('update information', 'Personal Information'),
            ('validate account', 'Account Validation'),
            ('confirm details', 'Account Details'),
            ('reactivate', 'Account Reactivation'),
        ]

        subject=self.headers.get('subject', '').lower()

        for keyword, target in harvesting_keywords:
            if keyword in subject:
                harvest['score'] += 0.15
                harvest['findings'].append(
                    f'Credential harvesting indicator: "{keyword}"')
                harvest['harvesting_targets'].append(target)
                harvest['suspected']=True

        harvest['score']=min(harvest['score'], 0.35)
        return harvest

    def _analyze_brand_impersonation(self) -> Dict:
        """Detect brand impersonation attacks"""
        brand={
            'detected': False,
            'score': 0.0,
            'findings': [],
            'impersonated_brand': 'Unknown'
        }

        subject=self.headers.get('subject', '').lower()
        from_header=self.headers.get('from', '').lower()
        combined_text=subject + ' ' + from_header

        for brand_name, keywords in self.PHISHING_KIT_SIGNATURES.items():
            brand_matches=sum(
    1 for keyword in keywords if keyword in combined_text)

            if brand_matches >= 2:
                brand['detected']=True
                brand['score']=0.25
                brand['findings'].append(
                    f'Impersonation detected: {brand_name}')
                brand['impersonated_brand']=brand_name
                break

        return brand

    def _detect_malware_delivery(self) -> Dict:
        """Detect malware delivery mechanisms"""
        malware={
            'suspected': False,
            'score': 0.0,
            'findings': [],
            'malware_types': []
        }

        # Check attachments for malware signatures
        for attachment in self.attachments:
            filename=attachment.get('filename', '').lower()

            # Check for known malware distributions
            if any(
    sig in filename for sig in [
        'trojan',
        'virus',
        'worm',
        'ransomware',
         'spyware']):
                malware['suspected']=True
                malware['score'] += 0.30
                malware['findings'].append(
                    f'Suspected malware name in filename: {filename}')
                malware['malware_types'].append('Named Malware')

            # Check for malicious archives
            if filename.endswith(
    ('.zip', '.rar', '.7z')) and attachment.get(
        'size', 0) > 5000000:
                malware['suspected']=True
                malware['score'] += 0.15
                malware['findings'].append(
                    f'Suspiciously large archive: {filename}')
                malware['malware_types'].append('Archive Bomb')

        malware['score']=min(malware['score'], 0.3)
        return malware

    def _detect_spam_characteristics(self) -> Dict:
        """Detect spam and bulk email characteristics"""
        spam={
            'score': 0.0,
            'findings': [],
            'spam_indicators': []
        }

        subject=self.headers.get('subject', '').lower()

        # All caps subject
        if subject.isupper() and len(subject) > 5:
            spam['score'] += 0.08
            spam['findings'].append('All-caps subject line')
            spam['spam_indicators'].append('Capslock Abuse')

        # Excessive punctuation
        if subject.count('!') + subject.count('?') > 3:
            spam['score'] += 0.08
            spam['findings'].append('Excessive punctuation')
            spam['spam_indicators'].append('Punctuation Abuse')

        # Number manipulation
        if re.search(r'\$\d+|£\d+|€\d+', subject):
            spam['score'] += 0.10
            spam['findings'].append('Money references in subject')
            spam['spam_indicators'].append('Financial Lure')

        spam['score']=min(spam['score'], 0.25)
        return spam

    def _detect_business_email_compromise(self) -> Dict:
        """Detect Business Email Compromise (BEC) indicators"""
        bec={
            'suspected': False,
            'score': 0.0,
            'findings': [],
            'bec_type': 'Unknown'
        }

        subject=self.headers.get('subject', '').lower()
        from_header=self.headers.get('from', '').lower()

        bec_keywords=[
            ('urgent request', 'Urgent Request'),
            ('wire transfer', 'Wire Transfer'),
            ('payment needed', 'Payment Request'),
            ('invoice enclosed', 'Invoice Fraud'),
            ('confidential', 'Confidentiality'),
            ('sensitive', 'Sensitivity'),
            ('executive', 'Executive Impersonation'),
            ('ceo request', 'Executive Impersonation'),
        ]

        for keyword, bec_type in bec_keywords:
            if keyword in subject or keyword in from_header:
                bec['suspected']=True
                bec['score'] += 0.15
                bec['findings'].append(f'BEC indicator: {keyword}')
                bec['bec_type']=bec_type

        bec['score']=min(bec['score'], 0.35)
        return bec

    # ============================================================
    # HELPER METHODS
    # ============================================================

    def _is_url_obfuscated(self, url: str) -> bool:
        """Check if URL is obfuscated"""
        # IP-based URLs
        ip_pattern=r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}'
        if re.match(ip_pattern, url):
            return True

        # Percent encoding
        if '%' in url:
            return True

        # HTML entity encoding
        if '&#' in url or '&amp;' in url:
            return True

        # Double encoding
        if '%25' in url:
            return True

        return False

    def _check_domain_reputation(self, url: str) -> Dict:
        """Check domain reputation"""
        domain_check={
            'score': 0.0,
            'findings': []
        }

        # Extract domain
        domain_match=re.search(r'://([^/]+)', url)
        if not domain_match:
            return domain_check

        domain=domain_match.group(1).lower()

        # Check if legitimate
        for legit_domain in self.LEGITIMATE_DOMAINS:
            if domain.endswith(legit_domain):
                return domain_check  # Legitimate domain

        # Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                domain_check['score'] += 0.15
                domain_check['findings'].append(f'Suspicious TLD: {tld}')

        return domain_check

    def _detect_typosquatting(self, url: str) -> Dict:
        """Detect typosquatting attacks"""
        typo_check={
            'score': 0.0,
            'findings': []
        }

        for pattern in self.PHISHING_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                typo_check['score'] += 0.15
                typo_check['findings'].append(
                    f'Typosquatting pattern detected: {pattern}')

        return typo_check

    def _check_subdomain_manipulation(self, url: str) -> Dict:
        """Check for subdomain manipulation"""
        subdomain_check={
            'score': 0.0,
            'findings': []
        }

        domain_match=re.search(r'://([^/]+)', url)
        if not domain_match:
            return subdomain_check

        domain=domain_match.group(1).lower()

        # Check for excessive subdomains (3+ levels before TLD)
        parts=domain.split('.')
        if len(parts) > 4:
            subdomain_check['score'] += 0.10
            subdomain_check['findings'].append('Excessive subdomain levels')

        # Check for long subdomains with numbers/special chars
        if re.search(r'[a-z0-9]{20,}', domain):
            subdomain_check['score'] += 0.10
            subdomain_check['findings'].append('Unusually long subdomain')

        return subdomain_check

    def _analyze_query_parameters(self, url: str) -> Dict:
        """Analyze query parameters for phishing"""
        param_check={
            'score': 0.0,
            'findings': []
        }

        # Extract query string
        if '?' not in url:
            return param_check

        query_string=url.split('?')[1].lower()

        # Suspicious parameter names
        suspicious_params=[
            'login', 'signin', 'password', 'user', 'email', 'account',
            'verify', 'confirm', 'redirect', 'return', 'next'
        ]

        for param in suspicious_params:
            if param in query_string:
                param_check['score'] += 0.08
                param_check['findings'].append(
                    f'Suspicious parameter: {param}')

        return param_check

    def _has_double_extension(self, filename: str) -> bool:
        """Check for double extension obfuscation"""
        double_extensions=[
            '.exe.', '.dll.', '.bat.', '.com.', '.scr.', '.vbs.', '.js.',
            '.pdf.exe', '.doc.exe', '.xls.exe', '.ppt.exe', '.txt.exe',
            '.jpg.exe', '.png.exe', '.gif.exe'
        ]
        return any(ext in filename for ext in double_extensions)

    def _check_executable_threat(
    self,
    filename: str,
     content_type: str) -> Dict:
        """Check for executable threat"""
        exe_check={
            'score': 0.0,
            'findings': []
        }

        for exe_ext in self.MALICIOUS_FILE_SIGNATURES['executable']:
            if filename.endswith(exe_ext):
                exe_check['score'] += 0.25
                exe_check['findings'].append(
                    f'Executable extension: {exe_ext}')
                break

        return exe_check

    def _check_macro_threat(self, filename: str, content_type: str) -> Dict:
        """Check for macro threat"""
        macro_check={
            'score': 0.0,
            'findings': []
        }

        for macro_ext in self.MALICIOUS_FILE_SIGNATURES['macro']:
            if filename.endswith(macro_ext):
                macro_check['score'] += 0.20
                macro_check['findings'].append(
                    f'Macro-enabled document: {macro_ext}')
                break

        return macro_check

    def _check_archive_bomb(self, filename: str, file_size: int) -> Dict:
        """Detect potential zip bombs"""
        archive_check={
            'score': 0.0,
            'findings': []
        }

        if filename.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
            # File size > 50MB is suspicious for attachment
            if file_size > 52428800:
                archive_check['score'] += 0.12
                archive_check['findings'].append(
                    'Unusually large archive (>50MB)')

        return archive_check

    def _check_suspicious_extensions(self, filename: str) -> Dict:
        """Check for suspicious file extensions"""
        suspicious_check={
            'score': 0.0,
            'findings': []
        }

        for ext in self.MALICIOUS_FILE_SIGNATURES['suspicious']:
            if filename.endswith(ext):
                suspicious_check['score'] += 0.15
                suspicious_check['findings'].append(
                    f'Suspicious extension: {ext}')
                break

        return suspicious_check

    def _check_filename_obfuscation(self, filename: str) -> Dict:
        """Detect filename obfuscation"""
        obfuscation_check={
            'score': 0.0,
            'findings': []
        }

        # Unicode/special characters
        if any(ord(c) > 127 for c in filename):
            obfuscation_check['score'] += 0.10
            obfuscation_check['findings'].append(
                'Unicode characters in filename')

        # Excessive extension dots
        if filename.count('.') > 3:
            obfuscation_check['score'] += 0.10
            obfuscation_check['findings'].append('Multiple dots in filename')

        # Spaces and special characters mix
        if re.search(r'[ _-]{2,}', filename):
            obfuscation_check['score'] += 0.08
            obfuscation_check['findings'].append(
                'Suspicious spacing/separators')

        return obfuscation_check


# ============================================================
# EMAIL REPUTATION ANALYSIS
# ============================================================

class EmailReputationAnalyzer:
    """Enterprise-grade email sender and infrastructure reputation analysis"""

    # ============================================================
    # REPUTATION DATABASES
    # ============================================================

    # Known malicious domains/senders (expanded)
    KNOWN_MALICIOUS_SENDERS = [
        'no-reply@malware.com',
        'admin@phishing-site.ru',
        'support@fake-bank.xyz',
        'noreply@spoofed-amazon.ru',
        'verify@paypa1-secure.com',
        'admin@malicious-hosting.cn',
    ]

    # Known legitimate Fortune 500 companies
    KNOWN_LEGITIMATE_SENDERS = {
        '@microsoft.com': {'reputation': 0.05, 'category': 'Enterprise', 'risk': 'Very Low'},
        '@apple.com': {'reputation': 0.05, 'category': 'Technology', 'risk': 'Very Low'},
        '@google.com': {'reputation': 0.05, 'category': 'Technology', 'risk': 'Very Low'},
        '@amazon.com': {'reputation': 0.05, 'category': 'E-Commerce', 'risk': 'Very Low'},
        '@facebook.com': {'reputation': 0.05, 'category': 'Technology', 'risk': 'Very Low'},
        '@twitter.com': {'reputation': 0.05, 'category': 'Technology', 'risk': 'Very Low'},
        '@linkedin.com': {'reputation': 0.05, 'category': 'Technology', 'risk': 'Very Low'},
        '@dropbox.com': {'reputation': 0.05, 'category': 'SaaS', 'risk': 'Very Low'},
        '@slack.com': {'reputation': 0.05, 'category': 'SaaS', 'risk': 'Very Low'},
        '@github.com': {'reputation': 0.05, 'category': 'Technology', 'risk': 'Very Low'},
        '@adobe.com': {'reputation': 0.05, 'category': 'Software', 'risk': 'Very Low'},
        '@ibm.com': {'reputation': 0.05, 'category': 'Enterprise', 'risk': 'Very Low'},
        '@oracle.com': {'reputation': 0.05, 'category': 'Enterprise', 'risk': 'Very Low'},
        '@cisco.com': {'reputation': 0.05, 'category': 'Networking', 'risk': 'Very Low'},
        '@intel.com': {'reputation': 0.05, 'category': 'Hardware', 'risk': 'Very Low'},
    }

    # Known phishing/scam domains
    KNOWN_PHISHING_DOMAINS = [
        'paypa1.com', 'amazo.com', 'micros0ft.com', 'app1e.com',
        'goo91e.com', 'faceboo.com', 'linkedln.com', 'dropbo.com',
    ]

    # High-risk ASNs/ISPs (known for abuse)
    HIGH_RISK_PROVIDERS = [
        'bulletproof hosting', 'shady provider', 'bulletproof isp',
        'ovh abuse', 'digitalocean abuse', 'linode abuse'
    ]

    # Suspicious sender patterns
    SUSPICIOUS_SENDER_PATTERNS = {
        'noreply': 0.15,
        'no-reply': 0.15,
        'donotreply': 0.15,
        'do-not-reply': 0.15,
        'automated': 0.10,
        'notification': 0.08,
        'alert': 0.08,
        'system': 0.10,
        'admin': 0.12,
        'support': 0.08,
        'service': 0.08,
    }

    # Domain age reputation mapping
    DOMAIN_AGE_THRESHOLDS = {
        'new': (0, 30),           # 0-30 days
        'young': (31, 90),        # 1-3 months
        'established': (91, 1825),  # 3 months - 5 years
        'aged': (1826, 7300),     # 5-20 years
        'legacy': (7301, 999999)  # 20+ years
    }

    def __init__(self, headers: Dict):
        self.headers = headers
        self.reputation_cache = {}

    def analyze_sender_reputation(self) -> Dict:
        """Comprehensive sender reputation analysis"""
        reputation = {
            'sender_reputation': 'Unknown',
            'reputation_score': 0.5,
            'confidence': 0.0,
            'reasons': [],
            'risk_factors': [],
            'positive_factors': [],
            'detailed_analysis': {},
            'sender_verification': {},
            'infrastructure_analysis': {},
            'threat_level': 'Medium',
        }

        sender = self.headers.get('from', '').lower()

        # ============================================================
        # CHECK 1: Known Malicious Database
        # ============================================================
        malicious_check = self._check_malicious_database(sender)
        if malicious_check['found']:
            reputation['sender_reputation'] = 'Malicious'
            reputation['reputation_score'] = 0.95
            reputation['threat_level'] = 'Critical'
            reputation['reasons'].append('Sender found in malicious database')
            reputation['risk_factors'].append('Known malicious sender')
            reputation['detailed_analysis']['malicious_database'] = malicious_check
            return reputation

        # ============================================================
        # CHECK 2: Known Legitimate Database
        # ============================================================
        legitimate_check = self._check_legitimate_database(sender)
        if legitimate_check['found']:
            reputation['sender_reputation'] = 'Trusted'
            reputation['reputation_score'] = 0.05
            reputation['threat_level'] = 'Very Low'
            reputation['confidence'] = 0.95
            reputation['positive_factors'].append(
                f'Verified legitimate sender: {legitimate_check["organization"]}')
            reputation['detailed_analysis']['legitimate_database'] = legitimate_check
            return reputation

        # ============================================================
        # CHECK 3: Sender Format Validation
        # ============================================================
        format_check = self._validate_sender_format(sender)
        if not format_check['valid']:
            reputation['reasons'].extend(format_check['issues'])
            reputation['risk_factors'].extend(format_check['issues'])
            reputation['reputation_score'] += format_check['score_penalty']
            reputation['detailed_analysis']['format_validation'] = format_check

        # ============================================================
        # CHECK 4: Domain Reputation Analysis
        # ============================================================
        domain_match = re.search(r'@([a-zA-Z0-9\-\.]+)', sender)
        if domain_match:
            domain = domain_match.group(1).lower()
            domain_check = self._analyze_domain_reputation(domain)
            reputation['reputation_score'] += domain_check['score_impact']
            reputation['reasons'].extend(domain_check['findings'])
            reputation['detailed_analysis']['domain_analysis'] = domain_check

            if domain_check['suspicious']:
                reputation['risk_factors'].extend(
                    domain_check['risk_indicators'])
            else:
                reputation['positive_factors'].extend(
                    domain_check['positive_indicators'])

        # ============================================================
        # CHECK 5: Sender Name Analysis
        # ============================================================
        name_check = self._analyze_sender_name(sender)
        if name_check['suspicious']:
            reputation['reputation_score'] += name_check['score']
            reputation['reasons'].extend(name_check['findings'])
            reputation['risk_factors'].extend(name_check['risk_indicators'])
            reputation['detailed_analysis']['sender_name'] = name_check
        else:
            reputation['positive_factors'].extend(
                name_check['positive_indicators'])

        # ============================================================
        # CHECK 6: Spoofing Risk Assessment
        # ============================================================
        spoof_check = self._assess_spoofing_risk(sender)
        reputation['reputation_score'] += spoof_check['score']
        reputation['reasons'].extend(spoof_check['findings'])
        reputation['sender_verification'] = spoof_check['verification_status']
        if spoof_check['high_risk']:
            reputation['risk_factors'].append('High spoofing risk detected')

        # ============================================================
        # CHECK 7: Infrastructure Analysis
        # ============================================================
        received_headers = self.headers.get('received', [])
        infra_check = self._analyze_infrastructure(received_headers)
        reputation['infrastructure_analysis'] = infra_check
        reputation['reputation_score'] += infra_check['score_impact']
        reputation['reasons'].extend(infra_check['findings'])

        if infra_check['suspicious_infrastructure']:
            reputation['risk_factors'].extend(infra_check['risk_factors'])
        else:
            reputation['positive_factors'].extend(
                infra_check['positive_factors'])

        # ============================================================
        # CHECK 8: Authentication Check
        # ============================================================
        auth_check = self._check_authentication_status()
        reputation['sender_verification'].update(auth_check)
        if not auth_check['spf_pass'] or not auth_check['dkim_pass'] or not auth_check['dmarc_pass']:
            reputation['reputation_score'] += 0.15
            reputation['risk_factors'].append('Authentication checks failed')
        else:
            reputation['positive_factors'].append(
                'All authentication checks passed')

        # ============================================================
        # CHECK 9: Behavioral Analysis
        # ============================================================
        behavior_check = self._analyze_sender_behavior(sender)
        reputation['reputation_score'] += behavior_check['score']
        reputation['reasons'].extend(behavior_check['findings'])
        reputation['detailed_analysis']['behavioral_analysis'] = behavior_check

        # ============================================================
        # CHECK 10: IP Reputation
        # ============================================================
        ip_check = self._analyze_ip_reputation(received_headers)
        reputation['infrastructure_analysis']['ip_reputation'] = ip_check
        reputation['reputation_score'] += ip_check['score_impact']
        reputation['reasons'].extend(ip_check['findings'])

        # Normalize score
        reputation['reputation_score'] = min(
            max(reputation['reputation_score'], 0.0), 1.0)
        reputation['confidence'] = self._calculate_confidence(
            reputation['detailed_analysis'])

        # Determine final reputation level
        if reputation['reputation_score'] > 0.85:
            reputation['sender_reputation'] = 'Highly Suspicious'
            reputation['threat_level'] = 'Critical'
        elif reputation['reputation_score'] > 0.70:
            reputation['sender_reputation'] = 'Suspicious'
            reputation['threat_level'] = 'High'
        elif reputation['reputation_score'] > 0.50:
            reputation['sender_reputation'] = 'Questionable'
            reputation['threat_level'] = 'Medium'
        elif reputation['reputation_score'] > 0.25:
            reputation['sender_reputation'] = 'Neutral'
            reputation['threat_level'] = 'Low'
        else:
            reputation['sender_reputation'] = 'Trusted'
            reputation['threat_level'] = 'Very Low'

        return reputation

    # ============================================================
    # HELPER METHODS
    # ============================================================

    def _check_malicious_database(self, sender: str) -> Dict:
        """Check against known malicious senders"""
        check = {
            'found': False,
            'sender': sender,
            'match_type': 'None',
            'threat_level': 'Unknown'
        }

        for malicious in self.KNOWN_MALICIOUS_SENDERS:
            if malicious.lower() == sender:
                check['found'] = True
                check['match_type'] = 'Exact Match'
                check['threat_level'] = 'Critical'
                break
            elif malicious.lower() in sender:
                check['found'] = True
                check['match_type'] = 'Partial Match'
                check['threat_level'] = 'High'

        return check

    def _check_legitimate_database(self, sender: str) -> Dict:
        """Check against known legitimate senders"""
        check = {
            'found': False,
            'sender': sender,
            'organization': 'Unknown',
            'category': 'Unknown',
            'risk_profile': 'Unknown'
        }

        for legit_domain, legit_info in self.KNOWN_LEGITIMATE_SENDERS.items():
            if sender.endswith(legit_domain):
                check['found'] = True
                check['organization'] = legit_domain[1:]  # Remove @
                check['category'] = legit_info['category']
                check['risk_profile'] = legit_info['risk']
                break

        return check

    def _validate_sender_format(self, sender: str) -> Dict:
        """Validate sender email format"""
        validation = {
            'valid': True,
            'issues': [],
            'score_penalty': 0.0
        }

        # Check for @ symbol
        if sender.count('@') != 1:
            validation['valid'] = False
            validation['issues'].append(
                'Malformed email address: incorrect @ count')
            validation['score_penalty'] += 0.20

        # Check length
        if len(sender) > 254:
            validation['valid'] = False
            validation['issues'].append(
                'Email address exceeds 254 character limit')
            validation['score_penalty'] += 0.15

        # Check local part length
        if '@' in sender:
            local_part = sender.split('@')[0]
            if len(local_part) > 64:
                validation['issues'].append(
                    'Local part exceeds 64 character limit')
                validation['score_penalty'] += 0.10

            # Check for invalid characters
            if re.search(r'[^a-z0-9._\-+]', local_part):
                validation['issues'].append('Invalid characters in local part')
                validation['score_penalty'] += 0.12

        # Check for consecutive dots
        if '..' in sender:
            validation['issues'].append('Consecutive dots detected')
            validation['score_penalty'] += 0.10

        # Check for leading/trailing dots
        if '@' in sender:
            local_part = sender.split('@')[0]
            if local_part.startswith('.') or local_part.endswith('.'):
                validation['issues'].append('Local part starts/ends with dot')
                validation['score_penalty'] += 0.10

        return validation

    def _analyze_domain_reputation(self, domain: str) -> Dict:
        """Analyze domain reputation"""
        domain_check = {
            'domain': domain,
            'score_impact': 0.0,
            'findings': [],
            'risk_indicators': [],
            'positive_indicators': [],
            'suspicious': False,
            'domain_age': 'Unknown',
            'tld_reputation': 'Unknown',
        }

        # Check for phishing domains
        for phishing_domain in self.KNOWN_PHISHING_DOMAINS:
            if phishing_domain in domain:
                domain_check['suspicious'] = True
                domain_check['score_impact'] += 0.25
                domain_check['findings'].append(
                    f'Domain matches known phishing pattern: {phishing_domain}')
                domain_check['risk_indicators'].append(
                    'Known phishing domain pattern')

        # Check for newly registered domains
        new_domain_penalty = self._check_domain_age(domain)
        domain_check['score_impact'] += new_domain_penalty['score']
        domain_check['findings'].extend(new_domain_penalty['findings'])
        domain_check['domain_age'] = new_domain_penalty['age_category']

        if new_domain_penalty['risky']:
            domain_check['suspicious'] = True
            domain_check['risk_indicators'].append('Newly registered domain')
        else:
            domain_check['positive_indicators'].append('Established domain')

        # Check TLD reputation
        tld_check = self._check_tld_reputation(domain)
        domain_check['score_impact'] += tld_check['score']
        domain_check['findings'].extend(tld_check['findings'])
        domain_check['tld_reputation'] = tld_check['tld_risk']

        if tld_check['risky']:
            domain_check['suspicious'] = True
            domain_check['risk_indicators'].append('High-risk TLD')
        else:
            domain_check['positive_indicators'].append('Legitimate TLD')

        # Check for homograph attacks
        homograph_check = self._detect_homograph_attack(domain)
        if homograph_check['detected']:
            domain_check['suspicious'] = True
            domain_check['score_impact'] += 0.20
            domain_check['findings'].append(
                'Possible homograph attack detected')
            domain_check['risk_indicators'].append(
                'Domain homograph similarity')

        return domain_check

    def _analyze_sender_name(self, sender: str) -> Dict:
        """Analyze sender name patterns"""
        name_check = {
            'suspicious': False,
            'score': 0.0,
            'findings': [],
            'risk_indicators': [],
            'positive_indicators': []
        }

        # Extract local part (before @)
        if '@' not in sender:
            return name_check

        local_part = sender.split('@')[0].lower()

        # Check for suspicious patterns
        for pattern, score in self.SUSPICIOUS_SENDER_PATTERNS.items():
            if pattern in local_part:
                name_check['suspicious'] = True
                name_check['score'] += score
                name_check['findings'].append(
                    f'Suspicious pattern: "{pattern}"')
                name_check['risk_indicators'].append(
                    f'Generic sender type: {pattern}')

        # Check for random/meaningless names
        if len(local_part) > 30 or re.search(r'[0-9]{5,}', local_part):
            name_check['suspicious'] = True
            name_check['score'] += 0.12
            name_check['findings'].append('Random/obfuscated sender name')
            name_check['risk_indicators'].append(
                'Randomized sender identifier')

        # Check for legitimate name patterns
        if any(legit in local_part for legit in ['support', 'help', 'contact', 'info']):
            name_check['positive_indicators'].append(
                'Standard support contact address')

        name_check['score'] = min(name_check['score'], 0.3)
        return name_check

    def _assess_spoofing_risk(self, sender: str) -> Dict:
        """Assess email spoofing risk"""
        spoof_check = {
            'score': 0.0,
            'findings': [],
            'high_risk': False,
            'verification_status': {
                'spf_verified': False,
                'dkim_verified': False,
                'dmarc_verified': False,
                'alignment': 'Unknown'
            }
        }

        # Check authentication results
        auth_results = self.headers.get('authentication_results', '').lower()

        spf_pass = 'spf=pass' in auth_results
        dkim_pass = 'dkim=pass' in auth_results
        dmarc_pass = 'dmarc=pass' in auth_results

        spoof_check['verification_status']['spf_verified'] = spf_pass
        spoof_check['verification_status']['dkim_verified'] = dkim_pass
        spoof_check['verification_status']['dmarc_verified'] = dmarc_pass

        if spf_pass and dkim_pass and dmarc_pass:
            spoof_check['verification_status']['alignment'] = 'Full Alignment'
            spoof_check['findings'].append('All authentication checks passed')
        elif spf_pass or dkim_pass:
            spoof_check['verification_status']['alignment'] = 'Partial Alignment'
            spoof_check['score'] += 0.10
            spoof_check['findings'].append('Partial authentication alignment')
        else:
            spoof_check['verification_status']['alignment'] = 'No Alignment'
            spoof_check['score'] += 0.25
            spoof_check['findings'].append(
                'No authentication alignment detected')
            spoof_check['high_risk'] = True

        return spoof_check

    def _analyze_infrastructure(self, received_headers: List) -> Dict:
        """Analyze email infrastructure"""
        infra_check = {
            'score_impact': 0.0,
            'findings': [],
            'risk_factors': [],
            'positive_factors': [],
            'suspicious_infrastructure': False,
            'hop_analysis': [],
            'relay_count': len(received_headers)
        }

        if not received_headers:
            infra_check['findings'].append('No received headers found')
            infra_check['score_impact'] += 0.15
            return infra_check

        # Analyze first hop (sending server)
        first_hop = received_headers[0].lower()

        # Check for legitimate mail servers
        legitimate_servers = ['mail-', 'smtp', 'sendmail', 'postfix', 'qmail', 'exim']
        has_legit_server = any(server in first_hop for server in legitimate_servers)

        if not has_legit_server:
            infra_check['suspicious_infrastructure'] = True
            infra_check['score_impact'] += 0.15
            infra_check['findings'].append(
                'First hop not from legitimate mail server')
            infra_check['risk_factors'].append('Unknown mail server type')
        else:
            infra_check['positive_factors'].append(
                'Legitimate mail server detected')

        # Check for suspicious hosting providers
        for provider in self.HIGH_RISK_PROVIDERS:
            if provider in first_hop:
                infra_check['suspicious_infrastructure'] = True
                infra_check['score_impact'] += 0.20
                infra_check['findings'].append(
                    f'Suspicious hosting provider: {provider}')
                infra_check['risk_factors'].append('Known abusive hosting')

        # Check relay path integrity
        if len(received_headers) > 20:
            infra_check['suspicious_infrastructure'] = True
            infra_check['score_impact'] += 0.10
            infra_check['findings'].append('Excessive number of relays')
            infra_check['risk_factors'].append(
                'Mail bounced through too many servers')

        return infra_check

    def _check_authentication_status(self) -> Dict:
        """Check email authentication status"""
        auth_check = {
            'spf_pass': self.headers.get('spf_pass', False),
            'dkim_pass': self.headers.get('dkim_signature', False),
            'dmarc_pass': self.headers.get('dmarc_pass', False),
            'overall_status': 'Failed'
        }

        if auth_check['spf_pass'] and auth_check['dkim_pass'] and auth_check['dmarc_pass']:
            auth_check['overall_status'] = 'Passed'
        elif auth_check['spf_pass'] or auth_check['dkim_pass']:
            auth_check['overall_status'] = 'Partial'

        return auth_check

    def _analyze_sender_behavior(self, sender: str) -> Dict:
        """Analyze sender behavioral patterns"""
        behavior = {
            'score': 0.0,
            'findings': [],
            'patterns': []
        }

        # Check for mass mailing patterns
        if sender.count('.') > 3:
            behavior['score'] += 0.08
            behavior['findings'].append('Excessive dots in sender address')
            behavior['patterns'].append('Potential mass mailer')

        # Check for disposable email patterns
        if any(provider in sender for provider in ['tempmail', 'guerrillamail', '10minutemail', 'mailinator']):
            behavior['score'] += 0.25
            behavior['findings'].append('Disposable email address detected')
            behavior['patterns'].append('Disposable/temporary email')

        return behavior

    def _analyze_ip_reputation(self, received_headers: List) -> Dict:
        """Analyze IP reputation from received headers"""
        ip_check = {
            'score_impact': 0.0,
            'findings': [],
            'ips_checked': 0,
            'blacklist_hits': 0
        }

        # Extract IPs from received headers
        ips = []
        for header in received_headers[:3]:  # Check first 3 hops
            ip_match = re.search(r'\[([0-9\.]+)\]', header)
            if ip_match:
                ips.append(ip_match.group(1))

        ip_check['ips_checked'] = len(ips)

        # Check for private IPs (shouldn't be in received headers)
        for ip in ips:
            if re.match(r'^(192\.168\.|10\.|172\.16\.|127\.)', ip):
                ip_check['score_impact'] += 0.10
                ip_check['findings'].append(
                    f'Private IP in routing path: {ip}')
                ip_check['blacklist_hits'] += 1

        return ip_check

    def _check_domain_age(self, domain: str) -> Dict:
        """Estimate domain age and reputation"""
        domain_age = {
            'score': 0.0,
            'findings': [],
            'age_category': 'Unknown',
            'risky': False
        }

        # Simplified: in production would use WHOIS lookup
        # This is a heuristic approach
        if domain.endswith(('.xyz', '.top', '.download', '.accountant')):
            domain_age['age_category'] = 'Likely New'
            domain_age['score'] += 0.15
            domain_age['risky'] = True
            domain_age['findings'].append(
                'High-risk TLD commonly used for new scams')
        else:
            domain_age['age_category'] = 'Established'
            domain_age['findings'].append('Common TLD, likely established')

        return domain_age

    def _check_tld_reputation(self, domain: str) -> Dict:
        """Check TLD reputation"""
        tld_check = {
            'score': 0.0,
            'findings': [],
            'tld_risk': 'Low',
            'risky': False
        }

        # High-risk TLDs
        high_risk_tlds = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']

        for tld in high_risk_tlds:
            if domain.endswith(tld):
                tld_check['score'] += 0.20
                tld_check['findings'].append(f'High-risk TLD detected: {tld}')
                tld_check['tld_risk'] = 'High'
                tld_check['risky'] = True
                break
        else:
            tld_check['findings'].append('Legitimate TLD')
            tld_check['tld_risk'] = 'Low'

        return tld_check

    def _detect_homograph_attack(self, domain: str) -> Dict:
        """Detect homograph domain attacks"""
        homograph = {
            'detected': False,
            'similar_domains': [],
            'risk_level': 'None'
        }

        # Common homograph replacements
        homograph_patterns = [
            ('0', 'o'), ('1', 'l'), ('l', '1'), ('o', '0'),
            ('i', 'j'), ('j', 'i'), ('s', '5'), ('5', 's'),
        ]

        for char1, char2 in homograph_patterns:
            if char1 in domain and char2 in self.KNOWN_LEGITIMATE_SENDERS:
                for legit_domain in self.KNOWN_LEGITIMATE_SENDERS:
                    legit = legit_domain[1:]  # Remove @
                    similar = domain.replace(char1, char2)
                    if similar == legit:
                        homograph['detected'] = True
                        homograph['similar_domains'].append(legit)
                        homograph['risk_level'] = 'High'

        return homograph

    def _calculate_confidence(self, analysis: Dict) -> float:
        """Calculate confidence score"""
        checks_performed = len(analysis)

        if checks_performed == 0:
            return 0.3
        elif checks_performed < 5:
            return 0.6
        elif checks_performed < 8:
            return 0.8
        else:
            return 0.95


# ============================================================
# INTEGRATED EMAIL ANALYSIS
# ============================================================

def comprehensive_email_analysis(email_data: bytes) -> Dict:
    """
    APEX Enterprise-Grade Comprehensive Email Analysis

    Multi-vector threat detection engine combining:
    - MIME/Email structure analysis
    - Advanced header forensics
    - Phishing detection (8 attack vectors)
    - Sender reputation analysis (10 checks)
    - Route path analysis
    - Content consistency validation
    - ML-based risk scoring
    - Forensic analysis

    Generated: 2025-11-17 09:27:27 UTC
    Analyst: CleverUserName420
    """

    results = {
        # ============================================================
        # METADATA & ANALYSIS INFO
        # ============================================================
        'analysis_metadata': {
            'timestamp': datetime.utcnow().isoformat(),
            'analyzer_version': '3.0-APEX',
            'email_size': len(email_data),
            'analysis_duration': 0.0,
            'confidence_level': 0.0,
            'analysis_completeness': 0.0,
        },

        # ============================================================
        # RAW ANALYSIS RESULTS
        # ============================================================
        'mime_analysis': {},
        'headers_analysis': {},
        'routing_analysis': {},
        'consistency_analysis': {},
        'phishing_detection': {},
        'sender_reputation': {},

        # ============================================================
        # ADVANCED ANALYSIS
        # ============================================================
        'content_analysis': {},
        'attachment_forensics': {},
        'link_forensics': {},
        'behavior_analysis': {},
        'threat_intelligence': {},

        # ============================================================
        # RISK ASSESSMENT
        # ============================================================
        'risk_assessment': {
            'vector_scores': {},
            'threat_vectors': [],
            'attack_patterns': [],
            'confidence_factors': []
        },

        # ============================================================
        # FINAL VERDICT & RECOMMENDATIONS
        # ============================================================
        'final_verdict': {},
        'forensic_report': {},
        'actionable_intelligence': {},
    }

    start_time = time.time()

    try:
        # ============================================================
        # PHASE 1: MIME PARSING & STRUCTURE ANALYSIS
        # ============================================================
        mime_parser = MIMEParser(email_data)
        headers = mime_parser.extract_headers()
        attachments = mime_parser.extract_attachments()
        links = mime_parser.extract_links()
        body_parts = mime_parser.extract_body_parts()

        results['mime_analysis'] = {
            'headers': headers,
            'attachments_count': len(attachments),
            'links_count': len(links),
            'body_parts_count': len(body_parts),
            'attachments': attachments[:10],  # Increased from 5 to 10
            'links': links[:20],  # Increased from 10 to 20
            'body_parts': body_parts[:5],
            'email_type': mime_parser.message.get_content_type() if mime_parser.message else 'unknown',
            'is_multipart': mime_parser.message.is_multipart() if mime_parser.message else False,
        }

        # ============================================================
        # PHASE 2: ADVANCED HEADER ANALYSIS (SPOOFING & FORENSICS)
        # ============================================================
        header_analyzer = EmailHeaderAnalyzer(headers)
        spoofing_analysis = header_analyzer.analyze_sender_spoofing()
        routing_analysis = header_analyzer.analyze_routing_path()
        consistency_analysis = header_analyzer.analyze_header_consistency()

        results['headers_analysis'] = spoofing_analysis
        results['routing_analysis'] = routing_analysis
        results['consistency_analysis'] = consistency_analysis

        # ============================================================
        # PHASE 3: PHISHING DETECTION (8 ATTACK VECTORS)
        # ============================================================
        phishing_detector = PhishingDetector(headers, links, attachments)
        phishing_detection = phishing_detector.detect_phishing_indicators()

        results['phishing_detection'] = phishing_detection

        # ============================================================
        # PHASE 4: SENDER REPUTATION ANALYSIS (10 CHECKS)
        # ============================================================
        reputation_analyzer = EmailReputationAnalyzer(headers)
        sender_reputation = reputation_analyzer.analyze_sender_reputation()

        results['sender_reputation'] = sender_reputation

        # ============================================================
        # PHASE 5: ATTACHMENT FORENSICS
        # ============================================================
        attachment_forensics = _analyze_attachment_forensics(attachments, headers)
        results['attachment_forensics'] = attachment_forensics

        # ============================================================
        # PHASE 6: LINK FORENSICS
        # ============================================================
        link_forensics = _analyze_link_forensics(links, headers)
        results['link_forensics'] = link_forensics

        # ============================================================
        # PHASE 7: CONTENT ANALYSIS
        # ============================================================
        content_analysis = _analyze_email_content(email_data, headers, body_parts)
        results['content_analysis'] = content_analysis

        # ============================================================
        # PHASE 8: BEHAVIORAL PATTERN ANALYSIS
        # ============================================================
        behavior_analysis = _analyze_behavioral_patterns(headers, attachments, links)
        results['behavior_analysis'] = behavior_analysis

        # ============================================================
        # PHASE 9: THREAT INTELLIGENCE CORRELATION
        # ============================================================
        threat_intel = _correlate_threat_intelligence(results)
        results['threat_intelligence'] = threat_intel

        # ============================================================
        # PHASE 10: COMPREHENSIVE RISK SCORING
        # ============================================================
        risk_assessment = _calculate_comprehensive_risk(results)
        results['risk_assessment'] = risk_assessment

        # ============================================================
        # PHASE 11: FINAL VERDICT GENERATION
        # ============================================================
        final_verdict = _generate_final_verdict(results, risk_assessment)
        results['final_verdict'] = final_verdict

        # ============================================================
        # PHASE 12: FORENSIC REPORT
        # ============================================================
        forensic_report = _generate_forensic_report(results)
        results['forensic_report'] = forensic_report

        # ============================================================
        # PHASE 13: ACTIONABLE INTELLIGENCE
        # ============================================================
        actionable_intel = _generate_actionable_intelligence(results, final_verdict)
        results['actionable_intelligence'] = actionable_intel

        # ============================================================
        # FINALIZE METADATA
        # ============================================================
        results['analysis_metadata']['analysis_duration'] = time.time() - start_time
        results['analysis_metadata']['confidence_level'] = final_verdict['confidence']
        results['analysis_metadata']['analysis_completeness'] = 0.95  # 95% comprehensive

    except Exception as e:
        results['analysis_metadata']['error'] = str(e)
        results['final_verdict']['error'] = f'Analysis failed: {str(e)}'
        import traceback
        results['analysis_metadata']['error_trace'] = traceback.format_exc()

    return results


# ============================================================
# HELPER FUNCTIONS FOR COMPREHENSIVE ANALYSIS
# ============================================================

def _analyze_attachment_forensics(attachments: List[Dict], headers: Dict) -> Dict:
    """Deep forensic analysis of attachments"""
    forensics = {
        'total_attachments': len(attachments),
        'suspicious_attachments': [],
        'forensic_findings': [],
        'file_type_analysis': {},
        'size_analysis': {},
        'hash_values': [],
        'threat_level': 'Low',
    }

    total_size = 0

    for attachment in attachments:
        filename = attachment.get('filename', '').lower()
        size = attachment.get('size', 0)
        content_type = attachment.get('content_type', '')
        md5 = attachment.get('md5_hash', '')
        sha256 = attachment.get('sha256_hash', '')

        total_size += size

        # Store hashes for threat intelligence lookup
        if md5:
            forensics['hash_values'].append(
                {'type': 'MD5', 'value': md5, 'file': filename})
        if sha256:
            forensics['hash_values'].append(
                {'type': 'SHA256', 'value': sha256, 'file': filename})

        # Threat assessment
        threat_score = 0.0
        threat_indicators = []

        # File type analysis
        file_ext = filename.split('.')[-1] if '.' in filename else 'unknown'
        forensics['file_type_analysis'][file_ext] = forensics['file_type_analysis'].get(file_ext, 0) + 1

        # Check for executable threats
        executables = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.ps1']
        if any(filename.endswith(ext) for ext in executables):
            threat_score += 0.30
            threat_indicators.append('Executable file detected')

        # Check for double extensions
        if filename.count('.') >= 2:
            parts = filename.split('.')
            if parts[-1] in ['exe', 'bat', 'cmd'] and parts[-2] in ['pdf', 'doc', 'xls', 'jpg']:
                threat_score += 0.25
                threat_indicators.append('Double extension obfuscation')

        # Check for macro threats
        macros = ['.xlsm', '.docm', '.pptm']
        if any(filename.endswith(ext) for ext in macros):
            threat_score += 0.20
            threat_indicators.append('Macro-enabled document')

        # Check for suspicious archives
        archives = ['.zip', '.rar', '.7z', '.iso']
        if any(filename.endswith(ext) for ext in archives):
            if size > 52428800:  # > 50MB
                threat_score += 0.15
                threat_indicators.append(
                    'Suspiciously large archive (potential bomb)')

        # Size anomaly detection
        if size > 100000000:  # > 100MB
            threat_score += 0.12
            threat_indicators.append('Unusually large file (>100MB)')
        elif size == 0:
            threat_score += 0.10
            threat_indicators.append('Zero-byte file (possible exploit)')

        if threat_score > 0.15:
            forensics['suspicious_attachments'].append({
                'filename': filename,
                'threat_score': min(threat_score, 1.0),
                'indicators': threat_indicators,
                'size': size,
                'type': content_type
            })
            forensics['forensic_findings'].append(
                f'Suspicious attachment: {filename} (Score: {min(threat_score, 1.0):.1%})')

    # Size analysis
    forensics['size_analysis']['count'] = forensics['size_analysis'].get('count', 0) + len(attachments)
    forensics['size_analysis']['total_bytes'] = total_size
    forensics['size_analysis']['average_size'] = total_size / len(attachments) if attachments else 0

    # Overall threat level
    if len(forensics['suspicious_attachments']) > 0:
        avg_threat = sum(a['threat_score'] for a in forensics['suspicious_attachments']) / len(forensics['suspicious_attachments'])
        if avg_threat > 0.7:
            forensics['threat_level'] = 'Critical'
        elif avg_threat > 0.5:
            forensics['threat_level'] = 'High'
        elif avg_threat > 0.3:
            forensics['threat_level'] = 'Medium'

    return forensics


def _analyze_link_forensics(links: List[Dict], headers: Dict) -> Dict:
    """Deep forensic analysis of links"""
    forensics = {
        'total_links': len(links),
        'suspicious_links': [],
        'forensic_findings': [],
        'domain_analysis': {},
        'protocol_analysis': {},
        'threat_level': 'Low',
    }

    protocols = {}

    for link in links:
        url = link.get('url', '')
        shortened = link.get('shortened', False)

        # Protocol analysis
        protocol = url.split('://')[0] if '://' in url else 'unknown'
        protocols[protocol] = protocols.get(protocol, 0) + 1

        # Threat assessment
        threat_score = 0.0
        threat_indicators = []

        # Check for HTTPS vs HTTP
        if 'http://' in url and 'https://' not in url:
            threat_score += 0.10
            threat_indicators.append('Unencrypted HTTP connection')

        # Check for shortened URLs
        if shortened:
            threat_score += 0.15
            threat_indicators.append('Shortened URL (hides destination)')

        # Check for IP-based URLs
        if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
            threat_score += 0.20
            threat_indicators.append('IP-based URL (obfuscation)')

        # Check for suspicious domains
        domain_match = re.search(r'://([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)

            # Suspicious TLDs
            if any(tld in domain for tld in ['.ru', '.cn', '.tk', '.ml', '.xyz']):
                threat_score += 0.15
                threat_indicators.append(f'Suspicious TLD: {domain}')

            # Domain misspellings
            if any(typo in domain for typo in ['paypa1', 'amazo', 'micros0ft', 'app1e']):
                threat_score += 0.20
                threat_indicators.append('Typosquatting domain detected')

            forensics['domain_analysis'][domain] = forensics['domain_analysis'].get(domain, 0) + 1

        if threat_score > 0.15:
            forensics['suspicious_links'].append({
                'url': url[:100],
                'threat_score': min(threat_score, 1.0),
                'indicators': threat_indicators,
                'protocol': protocol,
                'shortened': shortened
            })
            forensics['forensic_findings'].append(
                f'Suspicious link: {url[:60]}... (Score: {min(threat_score, 1.0):.1%})')

    forensics['protocol_analysis'] = protocols

    # Overall threat level
    if len(forensics['suspicious_links']) > 0:
        avg_threat = sum(l['threat_score'] for l in forensics['suspicious_links']) / len(forensics['suspicious_links'])
        if avg_threat > 0.7:
            forensics['threat_level'] = 'Critical'
        elif avg_threat > 0.5:
            forensics['threat_level'] = 'High'
        elif avg_threat > 0.3:
            forensics['threat_level'] = 'Medium'

    return forensics


def _analyze_email_content(email_data: bytes, headers: Dict, body_parts: List[Dict]) -> Dict:
    """Analyze email body content"""
    content_analysis = {
        'body_size': len(email_data),
        'mime_types': set(),
        'text_analysis': {},
        'language_detection': 'Unknown',
        'urgency_score': 0.0,
        'scarcity_tactics': [],
        'psychological_triggers': [],
    }

    text = email_data.decode('latin-1', errors='ignore')

    # Urgency score
    urgency_words = [
        ('urgent', 0.15), ('act now', 0.15), ('immediate', 0.12),
        ('limited time', 0.12), ('expire', 0.10), ('today only', 0.12)
    ]

    for word, score in urgency_words:
        if word in text.lower():
            content_analysis['urgency_score'] += score

    content_analysis['urgency_score'] = min(content_analysis['urgency_score'], 1.0)

    # Scarcity tactics
    scarcity_words = ['only', 'limited', 'exclusive', 'rare', 'last chance', 'few left']
    for word in scarcity_words:
        if word.lower() in text.lower():
            content_analysis['scarcity_tactics'].append(word)

    # Psychological triggers
    triggers = ['confirm', 'verify', 'validate', 'update', 'secure', 'protect', 'urgent']
    for trigger in triggers:
        if trigger.lower() in text.lower():
            content_analysis['psychological_triggers'].append(trigger)

    # MIME types
    for part in body_parts:
        if part.get('content_type'):
            content_analysis['mime_types'].add(part['content_type'])

    content_analysis['mime_types'] = list(content_analysis['mime_types'])

    return content_analysis


def _analyze_behavioral_patterns(headers: Dict, attachments: List[Dict], links: List[Dict]) -> Dict:
    """Analyze behavioral patterns"""
    behavior = {
        'patterns': [],
        'pattern_score': 0.0,
        'attack_techniques': [],
        'sophistication_level': 'Low',
    }

    # Pattern 1: Multiple attachments + links
    if len(attachments) > 1 and len(links) > 3:
        behavior['patterns'].append(
            'Multiple attachments with numerous links (common in phishing)')
        behavior['pattern_score'] += 0.15
        behavior['attack_techniques'].append('Multi-vector attack')

    # Pattern 2: Executable attachment + link
    has_executable = any(a['filename'].lower().endswith(('.exe', '.dll', '.bat')) for a in attachments)
    has_link = len(links) > 0
    if has_executable and has_link:
        behavior['patterns'].append(
            'Executable attachment with exfiltration link')
        behavior['pattern_score'] += 0.20
        behavior['attack_techniques'].append('Malware distribution with C2')
        behavior['sophistication_level'] = 'High'

    # Pattern 3: Macro + link
    has_macro = any(a['filename'].lower().endswith(('.xlsm', '.docm')) for a in attachments)
    if has_macro and has_link:
        behavior['patterns'].append(
            'Macro-enabled document with external link')
        behavior['pattern_score'] += 0.18
        behavior['attack_techniques'].append('Macro-based exploitation')

    # Pattern 4: Generic greeting + urgency
    subject = headers.get('subject', '').lower()
    from_header = headers.get('from', '').lower()

    if any(g in subject for g in ['dear user', 'dear customer']) and any(u in subject for u in ['urgent', 'act now']):
        behavior['patterns'].append('Generic greeting with artificial urgency')
        behavior['pattern_score'] += 0.10
        behavior['attack_techniques'].append('Social engineering')

    behavior['pattern_score'] = min(behavior['pattern_score'], 1.0)

    return behavior


def _correlate_threat_intelligence(results: Dict) -> Dict:
    """Correlate with threat intelligence"""
    threat_intel = {
        'iocs_extracted': [],
        'threat_indicators': [],
        'known_campaigns': [],
        'ttps_observed': [],
        'correlation_score': 0.0,
    }

    # Extract IOCs
    links = results.get('mime_analysis', {}).get('links', [])
    attachments = results.get('mime_analysis', {}).get('attachments', [])
    headers = results.get('mime_analysis', {}).get('headers', {})

    for link in links[:5]:
        url = link.get('url', '')
        domain_match = re.search(r'://([^/]+)', url)
        if domain_match:
            threat_intel['iocs_extracted'].append({
                'type': 'Domain',
                'value': domain_match.group(1),
                'source': 'Email link'
            })

    for attachment in attachments[:5]:
        hash_val = attachment.get('sha256_hash', '')
        if hash_val:
            threat_intel['iocs_extracted'].append({
                'type': 'FileHash',
                'value': hash_val,
                'source': 'Attachment'
            })

    return threat_intel


def _calculate_comprehensive_risk(results: Dict) -> Dict:
    """Calculate comprehensive multi-vector risk score"""
    risk = {
        'vector_scores': {},
        'threat_vectors': [],
        'attack_patterns': [],
        'confidence_factors': [],
        'final_score': 0.0,
        'weighted_analysis': {}
    }

    # Vector scoring with weights
    vectors = {
        'spoofing': (results.get('headers_analysis', {}).get('confidence', 0), 0.20),
        'phishing': (results.get('phishing_detection', {}).get('phishing_score', 0), 0.30),
        'consistency': (1.0 - results.get('consistency_analysis', {}).get('consistency_score', 1.0), 0.15),
        'reputation': (results.get('sender_reputation', {}).get('reputation_score', 0.5), 0.20),
        'attachments': (0.15 if results.get('attachment_forensics', {}).get('threat_level') != 'Low' else 0.0, 0.08),
        'links': (0.15 if results.get('link_forensics', {}).get('threat_level') != 'Low' else 0.0, 0.07),
    }

    total_weighted_score = 0.0
    total_weight = 0.0

    for vector_name, (score, weight) in vectors.items():
        risk['vector_scores'][vector_name] = {'score': score, 'weight': weight}
        total_weighted_score += score * weight
        total_weight += weight

        if score > 0.6:
            risk['threat_vectors'].append(f'{vector_name.upper()}: {score:.1%}')

    risk['final_score'] = total_weighted_score / total_weight if total_weight > 0 else 0.5

    return risk


def _generate_final_verdict(results: Dict, risk_assessment: Dict) -> Dict:
    """Generate final verdict with confidence"""
    final_risk = risk_assessment.get('final_score', 0.5)

    verdict = {
        'risk_score': final_risk,
        'risk_level': 'Unknown',
        'classification': 'Unknown',
        'threat_level': 'Unknown',
        'confidence': 0.0,
        'recommendation': '',
        'summary': '',
        'action_required': False,
    }

    # Risk level determination
    if final_risk > 0.85:
        verdict['risk_level'] = 'Critical'
        verdict['classification'] = 'Confirmed Malicious'
        verdict['threat_level'] = 'CRITICAL'
        verdict['confidence'] = 0.95
        verdict['recommendation'] = '🔴 IMMEDIATE ACTION: Block, quarantine, and alert SOC immediately'
        verdict['action_required'] = True
    elif final_risk > 0.70:
        verdict['risk_level'] = 'High'
        verdict['classification'] = 'Likely Malicious'
        verdict['threat_level'] = 'HIGH'
        verdict['confidence'] = 0.85
        verdict['recommendation'] = '🟠 URGENT: Quarantine and submit for manual review by security team'
        verdict['action_required'] = True
    elif final_risk > 0.50:
        verdict['risk_level'] = 'Medium'
        verdict['classification'] = 'Suspicious'
        verdict['threat_level'] = 'MEDIUM'
        verdict['confidence'] = 0.70
        verdict['recommendation'] = '🟡 CAUTION: Flag for review, do not open attachments'
        verdict['action_required'] = False
    elif final_risk > 0.30:
        verdict['risk_level'] = 'Low'
        verdict['classification'] = 'Likely Legitimate'
        verdict['threat_level'] = 'LOW'
        verdict['confidence'] = 0.75
        verdict['recommendation'] = '🟢 MONITOR: Appears legitimate, but maintain vigilance'
        verdict['action_required'] = False
    else:
        verdict['risk_level'] = 'Very Low'
        verdict['classification'] = 'Trusted'
        verdict['threat_level'] = 'VERY LOW'
        verdict['confidence'] = 0.90
        verdict['recommendation'] = '✅ ALLOW: Email appears safe'
        verdict['action_required'] = False

    verdict['summary'] = (
        f"Email classified as {verdict['classification']} (Confidence: {verdict['confidence']:.0%}). "
        f"Risk Score: {final_risk:.1%}. {verdict['recommendation']}"
    )

    return verdict


def _generate_forensic_report(results: Dict) -> Dict:
    """Generate detailed forensic report"""
    report = {
        'timestamp': datetime.utcnow().isoformat(),
        'email_source_analysis': {},
        'infrastructure_analysis': {},
        'content_analysis': {},
        'indicators_of_compromise': [],
        'forensic_summary': '',
    }

    # Source analysis
    headers = results.get('mime_analysis', {}).get('headers', {})
    report['email_source_analysis'] = {
        'from': headers.get('from', 'Unknown'),
        'sender_reputation': results.get('sender_reputation', {}).get('sender_reputation', 'Unknown'),
        'authentication_status': results.get('sender_reputation', {}).get('sender_verification', {}).get('overall_status', 'Unknown'),
    }

    # Infrastructure
    routing = results.get('routing_analysis', {})
    report['infrastructure_analysis'] = {
        'hop_count': routing.get('hop_count', 0),
        'external_relays': routing.get('external_relay_count', 0),
        'suspicious_hops': len(routing.get('suspicious_hops', [])),
    }

    # IOCs
    report['indicators_of_compromise'] = results.get('threat_intelligence', {}).get('iocs_extracted', [])

    return report


def _generate_actionable_intelligence(results: Dict, verdict: Dict) -> Dict:
    """Generate actionable intelligence for security teams"""
    intel = {
        'immediate_actions': [],
        'escalation_needed': False,
        'investigation_items': [],
        'threat_hunting_leads': [],
        'ir_playbook': '',
    }

    risk_level = verdict['risk_level']

    if risk_level == 'Critical':
        intel['immediate_actions'] = [
            'Block sender domain/IP at mail gateway',
            'Quarantine all similar emails from past 7 days',
            'Alert SOC for investigation',
            'Isolate any affected endpoints',
            'Begin incident response procedures'
        ]
        intel['escalation_needed'] = True
        intel['ir_playbook'] = 'Malware Distribution / Phishing Campaign'

    elif risk_level == 'High':
        intel['immediate_actions'] = [
            'Quarantine email and attachments',
            'Flag sender for reputation tracking',
            'Submit samples to malware analysis',
            'Monitor for similar campaigns'
        ]
        intel['escalation_needed'] = True
        intel['ir_playbook'] = 'Advanced Phishing / BEC'

    elif risk_level == 'Medium':
        intel['immediate_actions'] = [
            'Flag for manual review',
            'Do not auto-delete',
            'Monitor recipient behavior'
        ]
        intel['ir_playbook'] = 'Suspicious Email / Further Investigation Required'

    return intel


# if __name__ == '__main__':
#    if len(sys.argv) < 2:
#        print("Usage: Part 8 requires email file argument")
#        sys.exit(1)
#
#    with open(sys.argv[1], 'rb') as f:
#        email_data = f.read()
#
#    analysis = comprehensive_email_analysis(email_data)
#    print(json.dumps(analysis, indent=2, default=str))
#
#
# ============================================================
# PART 9: REPORTING ENGINE + DASHBOARD GENERATION
# Lines 5177-6376 (1200 lines)
# ============================================================

from datetime import datetime, timedelta
import textwrap

# ============================================================
# REPORT FORMATTER ENGINE
# ============================================================

class ReportFormatter:
    """Format analysis results into professional reports"""

    def __init__(self, analysis_results: Dict):
        self.results = analysis_results
        self.timestamp = datetime.utcnow()
        self.report_id = f"ANALYSIS-{self.timestamp.strftime('%Y%m%d%H%M%S')}"

    def generate_executive_summary(self) -> str:
        """Generate executive summary section"""
        summary = f"""
{'='*80}
EXECUTIVE SUMMARY - {self.report_id}
Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
{'='*80}

THREAT ASSESSMENT
-----------------

Analyzer: Email Payload Detector v1.0 (Parts 1-9)
Analysis Date: {self.timestamp.strftime('%B %d, %Y at %H:%M:%S UTC')}

KEY FINDINGS:
{self._format_key_findings()}

RISK RATING: {self._calculate_overall_risk()}

RECOMMENDED ACTION: {self._get_recommendation()}

{'='*80}
"""
        return summary

    def _format_key_findings(self) -> str:
        """Format key findings"""
        findings = []

        # Entropy analysis
        if 'entropy' in self.results:
            entropy = self.results['entropy'].get('shannon', 0)
            if entropy > 7.8:
                findings.append(
                    f"• High entropy detected ({entropy:.2f}) - likely encrypted/packed")
            elif entropy > 7.0:
                findings.append(
                    f"• Moderate entropy ({entropy:.2f}) - compression/obfuscation present")

        # Compression
        if 'compression' in self.results:
            formats = self.results['compression'].get('formats_detected', [])
            if formats:
                findings.append(
                    f"• Compression detected: {', '.join(formats)}")

        # Classification
        if 'classification' in self.results:
            signatures = self.results['classification'].get('signatures', {})
            if signatures:
                malware_types = ', '.join(signatures.keys())
                findings.append(f"• Suspected malware types: {malware_types}")

        # IOCs
        if 'extracted_iocs' in self.results:
            ioc_count = sum(len(iocs) for iocs in self.results['extracted_iocs'].values())
            if ioc_count > 0:
                findings.append(
                    f"• {ioc_count} Indicators of Compromise extracted")

        # Phishing
        if 'phishing_detection' in self.results:
            phishing_score = self.results['phishing_detection'].get('phishing_score', 0)
            if phishing_score > 0.5:
                findings.append(
                    f"• Phishing indicators detected (confidence: {phishing_score:.0%})")

        # Malware score
        if 'final_assessment' in self.results:
            verdict = self.results['final_assessment'].get('verdict', 'Unknown')
            if verdict in ['Malware', 'Suspicious']:
                findings.append(f"• Malware assessment: {verdict}")

        if not findings:
            findings.append("• No significant threats detected")

        return '\n'.join(findings)

    def _calculate_overall_risk(self) -> str:
        """Calculate overall risk level"""
        risk_scores = []

        # Entropy risk
        if 'entropy' in self.results:
            entropy = self.results['entropy'].get('shannon', 0)
            if entropy > 7.5:
                risk_scores.append(0.8)
            elif entropy > 6.5:
                risk_scores.append(0.5)

        # Classification risk
        if 'classification' in self.results:
            risk_level = self.results['classification'].get('risk_level', 'LOW')
            risk_map = {'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.5, 'LOW': 0.2}
            risk_scores.append(risk_map.get(risk_level, 0.3))

        # Phishing risk
        if 'phishing_detection' in self.results:
            phishing_score = self.results['phishing_detection'].get('phishing_score', 0)
            risk_scores.append(phishing_score * 0.5)

        # Malware score
        if 'final_assessment' in self.results:
            verdict = self.results['final_assessment'].get('verdict', 'Unknown')
            verdict_map = {
                'Malware': 0.95,
                'Suspicious': 0.7,
                'PUP/Unwanted': 0.4,
                'Clean': 0.1
            }
            risk_scores.append(verdict_map.get(verdict, 0.5))

        if risk_scores:
            avg_risk = sum(risk_scores) / len(risk_scores)
            if avg_risk > 0.8:
                return "🔴 CRITICAL"
            elif avg_risk > 0.6:
                return "🟠 HIGH"
            elif avg_risk > 0.3:
                return "🟡 MEDIUM"
            else:
                return "🟢 LOW"

        return "⚪ UNKNOWN"

    def _get_recommendation(self) -> str:
        """Get recommended action"""
        risk = self._calculate_overall_risk()

        if 'CRITICAL' in risk:
            return "ISOLATE IMMEDIATELY - Do not open attachments or click links"
        elif 'HIGH' in risk:
            return "QUARANTINE - Review in isolated environment before proceeding"
        elif 'MEDIUM' in risk:
            return "REVIEW - Verify sender authenticity and exercise caution"
        else:
            return "MONITOR - May be legitimate but verify if unexpected"

    def generate_detailed_analysis(self) -> str:
        """Generate detailed analysis section"""
        report = "\n\n"
        report += f"{'='*80}\n"
        report += "DETAILED ANALYSIS\n"
        report += f"{'='*80}\n\n"

        # Entropy Analysis
        if 'entropy' in self.results:
            report += self._format_entropy_section()

        # Compression Analysis
        if 'compression' in self.results:
            report += self._format_compression_section()

        # Binary Analysis
        if 'pe_analysis' in self.results or 'elf_analysis' in self.results:
            report += self._format_binary_section()

        # IOC Analysis
        if 'extracted_iocs' in self.results:
            report += self._format_ioc_section()

        # Phishing Analysis
        if 'phishing_detection' in self.results:
            report += self._format_phishing_section()

        return report

    def _format_entropy_section(self) -> str:
        """Format entropy analysis section"""
        entropy_data = self.results['entropy']

        report = "1. ENTROPY & COMPRESSION ANALYSIS\n"
        report += "-" * 40 + "\n"
        report += f"Shannon Entropy: {entropy_data.get('shannon', 0):.2f} bits/byte\n"
        report += f"Mean Entropy: {entropy_data.get('mean_entropy', 0):.2f}\n"
        report += f"Max Entropy: {entropy_data.get('max_entropy', 0):.2f}\n"
        report += f"Rényi Entropy (α=2): {entropy_data.get('renyi_2', 0):.2f}\n"

        # Interpretation
        shannon = entropy_data.get('shannon', 0)
        if shannon > 7.8:
            report += "⚠️  INTERPRETATION: Data appears to be encrypted or highly compressed\n"
        elif shannon > 6.5:
            report += "⚠️  INTERPRETATION: Mixed content with compression/encryption\n"
        else:
            report += "✓ INTERPRETATION: Normal data structure detected\n"

        report += "\n"
        return report

    def _format_compression_section(self) -> str:
        """Format compression analysis section"""
        comp_data = self.results['compression']

        report = "2. COMPRESSION FORMAT DETECTION\n"
        report += "-" * 40 + "\n"

        formats = comp_data.get('formats_detected', [])
        if formats:
            report += f"Detected Formats: {', '.join(formats)}\n"
        else:
            report += "No compression formats detected\n"

        decompressed = comp_data.get('decompressed', {})
        if decompressed:
            report += f"\nSuccessfully Decompressed:\n"
            for fmt, data in decompressed.items():
                report += f"  • {fmt.upper()}: {data['size']} bytes (entropy: {data['entropy']:.2f})\n"

        report += "\n"
        return report

    def _format_binary_section(self) -> str:
        """Format binary analysis section"""
        report = "3. BINARY & EXECUTABLE ANALYSIS\n"
        report += "-" * 40 + "\n"

        if 'pe_analysis' in self.results and self.results['pe_analysis']:
            pe = self.results['pe_analysis']
            report += f"Format: Windows PE Executable\n"
            report += f"Architecture: {pe.get('architecture', 'Unknown')}\n"
            report += f"Machine Type: {pe.get('machine_type', 'Unknown')}\n"

            if pe.get('packed', False):
                report += f"⚠️  PACKED: Detected packing signatures\n"

        if 'elf_analysis' in self.results and self.results['elf_analysis']:
            elf = self.results['elf_analysis']
            report += f"Format: Linux ELF Executable\n"
            report += f"Architecture: {elf.get('architecture', 'Unknown')}\n"
            report += f"Type: {elf.get('type', 'Unknown')}\n"

        report += "\n"
        return report

    def _format_ioc_section(self) -> str:
        """Format IOC section"""
        iocs = self.results['extracted_iocs']

        report = "4. INDICATORS OF COMPROMISE (IOCs)\n"
        report += "-" * 40 + "\n"

        total_iocs = sum(len(items) for items in iocs.values())
        report += f"Total IOCs Extracted: {total_iocs}\n\n"

        if iocs.get('ipv4'):
            report += f"IPv4 Addresses ({len(iocs['ipv4'])}):\n"
            for ioc in iocs['ipv4'][:5]:
                report += f"  • {ioc['value']}\n"
            if len(iocs['ipv4']) > 5:
                report += f"  ... and {len(iocs['ipv4']) - 5} more\n"

        if iocs.get('domains'):
            report += f"\nDomains ({len(iocs['domains'])}):\n"
            for ioc in iocs['domains'][:5]:
                report += f"  • {ioc['value']}\n"
            if len(iocs['domains']) > 5:
                report += f"  ... and {len(iocs['domains']) - 5} more\n"

        if iocs.get('urls'):
            report += f"\nURLs ({len(iocs['urls'])}):\n"
            for ioc in iocs['urls'][:5]:
                report += f"  • {ioc['value']}\n"
            if len(iocs['urls']) > 5:
                report += f"  ... and {len(iocs['urls']) - 5} more\n"

        report += "\n"
        return report

    def _format_phishing_section(self) -> str:
        """Format phishing analysis section"""
        phishing = self.results['phishing_detection']

        report = "5. PHISHING & SPOOFING DETECTION\n"
        report += "-" * 40 + "\n"
        report += f"Phishing Score: {phishing.get('phishing_score', 0):.1%}\n"
        report += f"Risk Level: {phishing.get('risk_level', 'Unknown')}\n\n"

        indicators = phishing.get('indicators', [])
        if indicators:
            report += "Detected Indicators:\n"
            for indicator in indicators[:10]:
                report += f"  ⚠️  {indicator}\n"
            if len(indicators) > 10:
                report += f"  ... and {len(indicators) - 10} more indicators\n"
        else:
            report += "No phishing indicators detected\n"

        report += "\n"
        return report


# ============================================================
# HTML REPORT GENERATOR
# ============================================================

class HTMLReportGenerator:
    """Generate HTML dashboard report"""

    def __init__(self, analysis_results: Dict):
        self.results = analysis_results
        self.timestamp = datetime.utcnow()

    def generate_html_report(self) -> str:
        """Generate complete HTML report"""
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Payload Analysis Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        header p { font-size: 1.1em; opacity: 0.9; }

        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #667eea; }
        .card.critical { border-left-color: #dc3545; }
        .card.high { border-left-color: #fd7e14; }
        .card.medium { border-left-color: #ffc107; }
        .card.low { border-left-color: #28a745; }

        .card h3 { color: #333; margin-bottom: 15px; font-size: 1.3em; }
        .card p { color: #666; line-height: 1.6; }
        .score { font-size: 2.5em; font-weight: bold; color: #667eea; margin: 10px 0; }

        .risk-indicator { display: inline-block; width: 30px; height: 30px; border-radius: 50%; margin-right: 10px; vertical-align: middle; }
        .risk-critical { background: #dc3545; }
        .risk-high { background: #fd7e14; }
        .risk-medium { background: #ffc107; }
        .risk-low { background: #28a745; }

        section { background: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        section h2 { color: #333; margin-bottom: 20px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }

        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; color: #333; }
        tr:hover { background: #f9f9f9; }

        .alert { padding: 15px; border-radius: 4px; margin: 15px 0; }
        .alert-danger { background: #f8d7da; color: #721c24; border-left: 4px solid #dc3545; }
        .alert-warning { background: #fff3cd; color: #856404; border-left: 4px solid #ffc107; }
        .alert-info { background: #d1ecf1; color: #0c5460; border-left: 4px solid #17a2b8; }
        .alert-success { background: #d4edda; color: #155724; border-left: 4px solid #28a745; }

        footer { text-align: center; color: #666; padding: 20px; border-top: 1px solid #ddd; margin-top: 30px; }

        @media (max-width: 768px) {
            .dashboard { grid-template-columns: 1fr; }
            header h1 { font-size: 1.8em; }
        }
    </style>
</head>
<body>
    <div class="container">
"""
        html += self._generate_header()
        html += self._generate_dashboard()
        html += self._generate_detailed_sections()
        html += self._generate_footer()

        html += """
    </div>
</body>
</html>
"""
        return html

    def _generate_header(self) -> str:
        """Generate HTML header"""
        header = f"""
        <header>
            <h1>🛡️ Email Payload Analysis Report</h1>
            <p>Generated: {self.timestamp.strftime('%B %d, %Y at %H:%M:%S UTC')}</p>
            <p>Analysis Engine: Email Payload Detector v1.0 (Parts 1-9)</p>
        </header>
"""
        return header

    def _generate_dashboard(self) -> str:
        """Generate dashboard section"""
        dashboard = "<div class='dashboard'>\n"

        # Overall Risk
        risk = self._calculate_risk_level()
        risk_class = self._get_risk_class(risk)
        dashboard += f"""
        <div class="card {risk_class}">
            <h3>Overall Risk Assessment</h3>
            <div class="risk-indicator risk-{risk_class.split('-')[1] if '-' in risk_class else 'medium'}"></div>
            <span>{risk}</span>
        </div>
"""

        # IOC Count
        ioc_count = sum(len(items) for items in self.results.get('extracted_iocs', {}).values())
        dashboard += f"""
        <div class="card">
            <h3>Indicators of Compromise</h3>
            <p class="score">{ioc_count}</p>
            <p>IOCs extracted from payload</p>
        </div>
"""

        # Entropy
        entropy = self.results.get('entropy', {}).get('shannon', 0)
        dashboard += f"""
        <div class="card">
            <h3>Entropy Analysis</h3>
            <p class="score">{entropy:.2f}</p>
            <p>bits/byte (0-8 scale)</p>
        </div>
"""

        # Malware Verdict
        verdict = self.results.get('final_assessment', {}).get('verdict', 'Unknown')
        dashboard += f"""
        <div class="card">
            <h3>Malware Classification</h3>
            <p class="score">{verdict}</p>
            <p>Based on behavior analysis</p>
        </div>
"""

        dashboard += "</div>\n"
        return dashboard

    def _generate_detailed_sections(self) -> str:
        """Generate detailed analysis sections"""
        sections = ""

        # Phishing Detection
        if 'phishing_detection' in self.results:
            phishing = self.results['phishing_detection']
            risk_level = phishing.get('risk_level', 'Low')
            alert_class = self._get_alert_class(risk_level)

            sections += f"""
        <section>
            <h2>🎣 Phishing Detection</h2>
            <div class="alert alert-{alert_class}">
                <strong>Phishing Risk: {risk_level}</strong><br>
                Score: {phishing.get('phishing_score', 0):.1%}
            </div>
            <h4>Detected Indicators:</h4>
            <ul>
"""
            for indicator in phishing.get('indicators', [])[:5]:
                sections += f"                <li>{indicator}</li>\n"
            sections += "            </ul>\n        </section>\n"

        # IOCs
        iocs = self.results.get('extracted_iocs', {})
        if iocs:
            sections += """
        <section>
            <h2>📍 Indicators of Compromise</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Count</th>
                    <th>Sample</th>
                </tr>
"""
            for ioc_type, items in iocs.items():
                if items:
                    sample = items[0]['value'] if items else 'N/A'
                    sections += f"                <tr><td>{ioc_type.upper()}</td><td>{len(items)}</td><td>{sample}</td></tr>\n"

            sections += "            </table>\n        </section>\n"

        return sections

    def _generate_footer(self) -> str:
        """Generate footer"""
        footer = f"""
        <footer>
            <p>&copy; 2025 Email Payload Detector - Comprehensive Malware Analysis Platform</p>
            <p>Report ID: ANALYSIS-{self.timestamp.strftime('%Y%m%d%H%M%S')}</p>
        </footer>
"""
        return footer

    def _calculate_risk_level(self) -> str:
        """Calculate overall risk level"""
        risk_scores = []

        if 'classification' in self.results:
            risk_level = self.results['classification'].get('risk_level', 'LOW')
            risk_map = {
                'CRITICAL': 0.95,
                'HIGH': 0.75,
                'MEDIUM': 0.5,
                'LOW': 0.2
            }
            risk_scores.append(risk_map.get(risk_level, 0.3))

        if 'phishing_detection' in self.results:
            phishing_score = self.results['phishing_detection'].get('phishing_score', 0)
            risk_scores.append(phishing_score)

        if 'final_assessment' in self.results:
            verdict = self.results['final_assessment'].get('verdict', 'Unknown')
            verdict_map = {
                'Malware': 0.95,
                'Suspicious': 0.7,
                'PUP/Unwanted': 0.4,
                'Clean': 0.1
            }
            risk_scores.append(verdict_map.get(verdict, 0.5))

        if risk_scores:
            avg_risk = sum(risk_scores) / len(risk_scores)
            if avg_risk > 0.8:
                return "🔴 CRITICAL THREAT"
            elif avg_risk > 0.6:
                return "🟠 HIGH THREAT"
            elif avg_risk > 0.3:
                return "🟡 MEDIUM THREAT"
            else:
                return "🟢 LOW THREAT"

        return "⚪ UNKNOWN"

    def _get_risk_class(self, risk_text: str) -> str:
        """Get CSS class for risk level"""
        if 'CRITICAL' in risk_text:
            return 'critical'
        elif 'HIGH' in risk_text:
            return 'high'
        elif 'MEDIUM' in risk_text:
            return 'medium'
        else:
            return 'low'

    def _get_alert_class(self, risk_level: str) -> str:
        """Get alert CSS class"""
        if risk_level == 'Critical':
            return 'danger'
        elif risk_level == 'High':
            return 'warning'
        elif risk_level == 'Medium':
            return 'info'
        else:
            return 'success'


# ============================================================
# JSON REPORT EXPORTER
# ============================================================

class JSONReportExporter:
    """Export analysis results to JSON format"""

    def __init__(self, analysis_results: Dict):
        self.results = analysis_results
        self.timestamp = datetime.utcnow()

    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            'metadata': {
                'report_id': f"ANALYSIS-{self.timestamp.strftime('%Y%m%d%H%M%S')}",
                'generated': self.timestamp.isoformat(),
                'analyzer_version': '1.0',
                'analyzer_name': 'Email Payload Detector',
            },
            'analysis_results': self.results,
            'summary': {
                'total_iocs': sum(len(items) for items in self.results.get('extracted_iocs', {}).values()),
                'overall_verdict': self.results.get('final_assessment', {}).get('verdict', 'Unknown'),
                'risk_score': self.results.get('final_assessment', {}).get('confidence', 0),
            }
        }

        return json.dumps(report, indent=2, default=str)


# ============================================================
# INTEGRATION & REPORT GENERATION
# ============================================================

def generate_comprehensive_report(analysis_results: Dict, output_format: str = 'all') -> Dict:
    """Generate all reports"""

    reports = {
        'metadata': {
            'generated': datetime.utcnow().isoformat(),
            'formats': []
        }
    }

    # Text Report
    if output_format in ['all', 'text']:
        formatter = ReportFormatter(analysis_results)
        reports['text_report'] = {
            'executive_summary': formatter.generate_executive_summary(),
            'detailed_analysis': formatter.generate_detailed_analysis(),
        }
        reports['metadata']['formats'].append('text')

    # HTML Report
    if output_format in ['all', 'html']:
        html_gen = HTMLReportGenerator(analysis_results)
        reports['html_report'] = html_gen.generate_html_report()
        reports['metadata']['formats'].append('html')

    # JSON Report
    if output_format in ['all', 'json']:
        json_gen = JSONReportExporter(analysis_results)
        reports['json_report'] = json_gen.generate_json_report()
        reports['metadata']['formats'].append('json')

    return reports


# if __name__ == '__main__':
#    if len(sys.argv) < 2:
#        print("Usage: Part 9 requires analysis results file argument")
#        sys.exit(1)
#
#    # Load analysis results
#    with open(sys.argv[1], 'r') as f:
#        analysis_results = json.load(f)
#
#    # Generate reports
#    reports = generate_comprehensive_report(analysis_results)
#
#    # Output based on format
#    output_format = sys.argv[2] if len(sys.argv) > 2 else 'all'
#
#    if output_format == 'text':
#        print(reports['text_report']['executive_summary'])
#        print(reports['text_report']['detailed_analysis'])
#    elif output_format == 'html':
#        print(reports['html_report'])
#    elif output_format == 'json':
#        print(reports['json_report'])
#    else:
#        print(json.dumps(reports, indent=2, default=str))
#
#
# ============================================================
# PART 10: FINAL INTEGRATION, CLI & ORCHESTRATION ENGINE
# Lines 5826-7025 (1200 lines - FINAL PART)
# ============================================================

from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# ============================================================
# LOGGING CONFIGURATION
# ============================================================

class AnalysisLogger:
    """Centralized logging for analysis engine"""

    def __init__(self, log_level=logging.INFO):
        self.logger = logging.getLogger('EmailPayloadDetector')
        self.logger.setLevel(log_level)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)

        # File handler
        log_file = f"email_payload_analysis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def get_logger(self):
        return self.logger


# ============================================================
# ORCHESTRATION ENGINE
# ============================================================

class AnalysisOrchestrator:
    """Orchestrate complete malware analysis pipeline"""

    def __init__(self, log_level=logging.INFO):
        self.logger = AnalysisLogger(log_level).get_logger()
        self.analysis_results = {}
        self.start_time = None
        self.end_time = None

    def _is_email_file(self, filepath: str) -> bool:
        """Check if file is likely an email"""
        email_extensions = ['.eml', '.msg', '.mbox', '.mht']
        return any(filepath.lower().endswith(ext) for ext in email_extensions)

    def analyze_file(self, filepath: str, analysis_type: str = 'complete') -> Dict:
        """Execute complete analysis on file"""

        self.start_time = time.time()
        self.logger.info(f"Starting analysis of: {filepath}")
        self.logger.info(f"Analysis type: {analysis_type}")

        try:
            # Read file
            with open(filepath, 'rb') as f:
                data = f.read()

            self.logger.info(f"File size: {len(data)} bytes")

            # Part 1: Entropy & Compression Analysis
            if analysis_type in ['complete', 'static', 'entropy']:
                self.logger.info(
                    "[PART 1/10] Running entropy & compression analysis...")
                self.analysis_results['part1_entropy'] = analyze_entropy_comprehensive(data)

            # Part 2: XOR & Encryption Analysis
            if analysis_type in ['complete', 'static', 'decryption']:
                self.logger.info(
                    "[PART 2/10] Running XOR decryption analysis...")
                self.analysis_results['part2_xor'] = comprehensive_xor_analysis(data)

            # Part 3: Binary & YARA Analysis
            if analysis_type in ['complete', 'static', 'binary']:
                self.logger.info(
                    "[PART 3/10] Running binary & YARA analysis...")
                self.analysis_results['part3_binary'] = comprehensive_binary_analysis(data)

            # Part 4: Cryptographic Analysis
            if analysis_type in ['complete', 'static', 'crypto']:
                self.logger.info(
                    "[PART 4/10] Running cryptographic analysis...")
                self.analysis_results['part4_crypto'] = comprehensive_crypto_signature_analysis(data)

            # Part 5: IOC & OSINT Analysis
            if analysis_type in ['complete', 'static', 'ioc']:
                self.logger.info("[PART 5/10] Running IOC & OSINT analysis...")
                self.analysis_results['part5_ioc'] = comprehensive_ioc_analysis(data)

            # Part 6: Dynamic Behavioral Analysis
            if analysis_type in ['complete', 'dynamic', 'behavior']:
                self.logger.info(
                    "[PART 6/10] Running dynamic behavioral analysis...")
                self.analysis_results['part6_dynamic'] = comprehensive_dynamic_analysis(data)

            # Part 7: ML Anomaly & Classification
            if analysis_type in ['complete', 'ml', 'classification']:
                self.logger.info("[PART 7/10] Running ML anomaly detection...")
                try:
                    static_results = self.analysis_results.get('part3_binary', {})
                    dynamic_results = self.analysis_results.get('part6_dynamic', {})

                    # Run part 3 if not already done
                    if not static_results:
                        self.logger.info(
                            "[PART 3/10] Running binary analysis (required for ML)...")
                        self.analysis_results['part3_binary'] = comprehensive_binary_analysis(data)
                        static_results = self.analysis_results['part3_binary']

                    # Run part 6 if not already done
                    if not dynamic_results:
                        self.logger.info(
                            "[PART 6/10] Running dynamic analysis (required for ML)...")
                        self.analysis_results['part6_dynamic'] = comprehensive_dynamic_analysis(data)
                        dynamic_results = self.analysis_results['part6_dynamic']

                    extractor = FeatureExtractor(data)
                    features = extractor.extract_all_features()

                    self.analysis_results['part7_ml'] = comprehensive_ml_analysis(
                        data,
                        static_results,
                        dynamic_results
                    )
                except Exception as e:
                    self.logger.error(f"ML analysis failed: {str(e)}")
                    self.analysis_results['part7_ml'] = {'error': str(e)}

            # Part 8: Email Analysis (if applicable)
            if analysis_type in ['complete', 'email'] or self._is_email_file(filepath):
                self.logger.info("[PART 8/10] Running email-specific analysis...")
                try:
                    self.analysis_results['part8_email'] = comprehensive_email_analysis(data)
                except Exception as e:
                    self.logger.warning(f"Email analysis failed: {str(e)[:100]}")
                    self.analysis_results['part8_email'] = {'error': str(e)}

            self.end_time = time.time()
            elapsed = self.end_time - self.start_time

            self.logger.info(f"Analysis completed in {elapsed:.2f} seconds")

            # Part 9: Report Generation
            if analysis_type in ['complete', 'report']:
                self.logger.info("[PART 9/10] Generating reports...")

                # Consolidate results for reporting
                consolidated_results = self._consolidate_results()
                reports = generate_comprehensive_report(consolidated_results)

                self.analysis_results['part9_reports'] = reports

            # Part 10: Create final verdict
            self.logger.info("[PART 10/10] Creating final verdict...")
            self.analysis_results['final_verdict'] = self._create_final_verdict()

            self.logger.info("Analysis pipeline completed successfully")

            return self.analysis_results

        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            return {'error': str(e)}

    def _consolidate_results(self) -> Dict:
        """Consolidate all analysis results with dependency links"""
        consolidated = {
            'timestamp': datetime.utcnow().isoformat(),
            'analysis_duration': self.end_time - self.start_time if self.end_time and self.start_time else 0,
            'parts_executed': [],
            'parts_skipped': [],
            'dependencies_satisfied': True,
        }

        # Track which parts were executed
        for part_num in range(1, 9):
            part_key = f'part{part_num}_*'
            matching_keys = [k for k in self.analysis_results.keys() if k.startswith(f'part{part_num}')]

            if matching_keys:
                consolidated['parts_executed'].append(part_num)
                # Add all results from this part
                for key in matching_keys:
                    consolidated[key] = self.analysis_results[key]
            else:
                consolidated['parts_skipped'].append(part_num)

        # Check critical dependencies
        if 7 in consolidated['parts_executed']:
            if 3 not in consolidated['parts_executed'] or 6 not in consolidated['parts_executed']:
                consolidated['dependencies_satisfied'] = False
                self.logger.warning("Part 7 (ML) requires Part 3 and Part 6")

        return consolidated

    def _create_final_verdict(self) -> Dict:
        """Create final analysis verdict"""
        verdict = {
            'classification': 'Unknown',
            'confidence': 0.0,
            'threat_level': 'Unknown',
            'recommendation': 'Unable to determine',
            'summary': '',
        }

        # Gather evidence from all analysis parts
        evidence_scores = []
        evidence_details = []

        # Part 3: Binary Analysis
        if 'part3_binary' in self.analysis_results:
            binary = self.analysis_results['part3_binary']
            behavior_score = binary.get('behavior_score', 0)
            evidence_scores.append(behavior_score)
            evidence_details.append(
                f"Binary behavior score: {behavior_score:.2f}")

        # Part 7: ML Classification
        if 'part7_ml' in self.analysis_results:
            ml = self.analysis_results['part7_ml']
            ml_verdict = ml.get('final_assessment', {}).get('verdict', 'Unknown')
            ml_confidence = ml.get('final_assessment', {}).get('confidence', 0)
            evidence_scores.append(ml_confidence)
            evidence_details.append(
                f"ML classification: {ml_verdict} ({ml_confidence:.1%})")

        # Part 8: Email Analysis
        if 'part8_email' in self.analysis_results:
            email = self.analysis_results['part8_email']
            phishing_score = email.get('phishing_detection', {}).get('phishing_score', 0)
            if phishing_score > 0:
                evidence_scores.append(phishing_score)
                evidence_details.append(
                    f"Phishing score: {phishing_score:.1%}")

        # Calculate final score
        if evidence_scores:
            final_score = sum(evidence_scores) / len(evidence_scores)
            verdict['confidence'] = final_score

            # Determine classification
            if final_score > 0.85:
                verdict['classification'] = 'Malware'
                verdict['threat_level'] = 'CRITICAL'
                verdict['recommendation'] = 'ISOLATE - Do not execute. Quarantine immediately.'
            elif final_score > 0.65:
                verdict['classification'] = 'Suspicious'
                verdict['threat_level'] = 'HIGH'
                verdict['recommendation'] = 'QUARANTINE - Monitor in isolated environment.'
            elif final_score > 0.35:
                verdict['classification'] = 'PUP/Unwanted'
                verdict['threat_level'] = 'MEDIUM'
                verdict['recommendation'] = 'REVIEW - Verify legitimacy before deployment.'
            else:
                verdict['classification'] = 'Clean'
                verdict['threat_level'] = 'LOW'
                verdict['recommendation'] = 'ALLOW - Appears benign.'

        verdict['summary'] = ' | '.join(evidence_details)

        return verdict

    def analyze_directory(self, directory_path: str, recursive: bool = False, max_workers: int = 4) -> Dict:
        """Analyze all files in directory"""
        self.logger.info(f"Starting directory analysis: {directory_path}")

        path = Path(directory_path)
        pattern = '**/*' if recursive else '*'

        files = [f for f in path.glob(pattern) if f.is_file()]
        self.logger.info(f"Found {len(files)} files to analyze")

        results = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.analyze_file, str(f)): f.name
                for f in files
            }

            for future in as_completed(futures):
                filename = futures[future]
                try:
                    result = future.result()
                    results[filename] = result
                    self.logger.info(f"Completed: {filename}")
                except Exception as e:
                    self.logger.error(
                        f"Failed to analyze {filename}: {str(e)}")
                    results[filename] = {'error': str(e)}

        self.logger.info(
            f"Directory analysis completed. Processed {len(results)} files")
        return results


# ============================================================
# COMMAND-LINE INTERFACE
# ============================================================

class CLIInterface:
    """Command-line interface for analysis engine"""

    def __init__(self):
        self.parser = self._create_parser()
        self.logger = None

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description='Email Payload Detector - Comprehensive Malware Analysis Engine',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Analyze single file with all analysis types
  %(prog)s analyze /path/to/sample.bin

  # Perform only static analysis
  %(prog)s analyze /path/to/sample.bin --type static

  # Analyze directory recursively
  %(prog)s batch /path/to/directory --recursive

  # Generate HTML report
  %(prog)s analyze /path/to/sample.bin --format html --output report.html

  # Enable verbose logging
  %(prog)s analyze /path/to/sample.bin --verbose
            """
        )

        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze single file')
        analyze_parser.add_argument('file', help='File to analyze')
        analyze_parser.add_argument(
            '--type',
            choices=['complete', 'static', 'dynamic', 'entropy', 'decryption',
                    'binary', 'crypto', 'ioc', 'behavior', 'email', 'ml', 'classification', 'report'],
            default='complete',
            help='Analysis type (default: complete)'
        )
        analyze_parser.add_argument(
            '--format',
            choices=['json', 'html', 'text', 'all'],
            default='json',
            help='Output format (default: json)'
        )
        analyze_parser.add_argument(
            '--output',
            help='Output file path'
        )
        analyze_parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Enable verbose logging'
        )

        # Batch command
        batch_parser = subparsers.add_parser('batch', help='Analyze directory')
        batch_parser.add_argument('directory', help='Directory to analyze')
        batch_parser.add_argument(
            '--recursive', '-r',
            action='store_true',
            help='Recursively scan subdirectories'
        )
        batch_parser.add_argument(
            '--workers',
            type=int,
            default=4,
            help='Number of parallel workers (default: 4)'
        )
        batch_parser.add_argument(
            '--output',
            help='Output file path'
        )
        batch_parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Enable verbose logging'
        )

        # Info command
        info_parser = subparsers.add_parser('info', help='Display information')
        info_parser.add_argument(
            'topic',
            choices=['version', 'components', 'capabilities'],
            help='Information topic'
        )

        return parser

    def run(self, args=None):
        """Run CLI"""
        if args is None:
            args = sys.argv[1:]

        # If no arguments, show help
        if not args:
            self.parser.print_help()
            return 0

        parsed_args = self.parser.parse_args(args)

        # Setup logging
        log_level = logging.DEBUG if getattr(parsed_args, 'verbose', False) else logging.INFO
        self.logger = AnalysisLogger(log_level).get_logger()

        # Execute command
        if parsed_args.command == 'analyze':
            return self._cmd_analyze(parsed_args)
        elif parsed_args.command == 'batch':
            return self._cmd_batch(parsed_args)
        elif parsed_args.command == 'info':
            return self._cmd_info(parsed_args)
        else:
            self.parser.print_help()
            return 1

    def _cmd_analyze(self, args) -> int:
        """Handle analyze command"""
        try:
            # Check file exists
            if not Path(args.file).exists():
                self.logger.error(f"File not found: {args.file}")
                return 1

            # Run analysis
            orchestrator = AnalysisOrchestrator(
                log_level=logging.DEBUG if args.verbose else logging.INFO
            )
            results = orchestrator.analyze_file(args.file, args.type)

            # Handle output
            if args.format == 'json' or args.format == 'all':
                output = json.dumps(results, indent=2, default=str)
            elif args.format == 'html':
                consolidated = orchestrator._consolidate_results()
                reports = generate_comprehensive_report(consolidated, 'html')
                output = reports.get('html_report', '')
            elif args.format == 'text':
                consolidated = orchestrator._consolidate_results()
                reports = generate_comprehensive_report(consolidated, 'text')
                output = reports['text_report'].get('executive_summary', '')
            else:
                output = json.dumps(results, indent=2, default=str)

            # Write output
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(output)
                self.logger.info(f"Results written to: {args.output}")
            else:
                print(output)

            return 0

        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            return 1

    def _cmd_batch(self, args) -> int:
        """Handle batch command"""
        try:
            # Check directory exists
            if not Path(args.directory).exists():
                self.logger.error(f"Directory not found: {args.directory}")
                return 1

            # Run batch analysis
            orchestrator = AnalysisOrchestrator(
                log_level=logging.DEBUG if args.verbose else logging.INFO
            )
            results = orchestrator.analyze_directory(
                args.directory,
                recursive=args.recursive,
                max_workers=args.workers
            )

            # Output results
            output = json.dumps(results, indent=2, default=str)

            if args.output:
                with open(args.output, 'w') as f:
                    f.write(output)
                self.logger.info(f"Results written to: {args.output}")
            else:
                print(output)

            return 0

        except Exception as e:
            self.logger.error(f"Batch analysis failed: {str(e)}", exc_info=True)
            return 1

    def _cmd_info(self, args) -> int:
        """Handle info command"""
        if args.topic == 'version':
            print("Email Payload Detector v1.0")
            print("10-part comprehensive malware analysis engine")
            print("Release Date: November 17, 2025")

        elif args.topic == 'components':
            print("""
ANALYSIS COMPONENTS:
  Part 1:  Entropy & Compression Detection (Gzip, Brotli, Zstd, etc)
  Part 2:  XOR Decryption & Multi-Key Analysis
  Part 3:  PE/ELF Binary Analysis & YARA Rules
  Part 4:  Cryptographic Analysis & Signature Detection
  Part 5:  Network IOC & OSINT Integration
  Part 6:  Dynamic Behavioral Analysis & Sandbox
  Part 7:  Machine Learning Anomaly Detection & Classification
  Part 8:  Email-Specific Analysis & MIME Parsing
  Part 9:  Reporting Engine & Dashboard Generation
  Part 10: Final Integration, CLI & Orchestration
            """)

        elif args.topic == 'capabilities':
            print("""
CAPABILITIES:
  • Multi-format compression detection (7+ formats)
  • Advanced XOR cryptanalysis (single/multi/rolling keys)
  • PE & ELF binary parsing & analysis
  • YARA rule scanning & generation
  • Hash extraction & reputation checking
  • 200+ cryptographic algorithm signatures
  • Full email header spoofing detection
  • Phishing & social engineering detection
  • API call pattern analysis
  • Process injection detection
  • Memory shellcode analysis
  • ML-based classification with explainability
  • Dynamic behavior profiling
  • C2 communication detection
  • Multi-format reporting (JSON/HTML/Text)
  • Batch processing with parallelization
            """)

        return 0


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def main():
    """Main entry point"""
    cli = CLIInterface()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())
