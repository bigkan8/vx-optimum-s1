# VerifiedX - Advanced Phishing Detection System

VerifiedX is a sophisticated phishing detection system that combines multiple analysis techniques to identify and analyze potential phishing attempts. It uses advanced machine learning models, technical URL analysis, and fact verification to provide comprehensive threat assessment.

## Features

- **Multi-Modal Analysis**:
  - Message content analysis using optimized RoBERTa model
  - Technical URL analysis with DNS, SSL, and domain verification
  - Fact checking with Perplexity API
  - RAG-enhanced analysis using Pinecone

- **Advanced URL Analysis**:
  - SSL certificate validation
  - Domain age and registration verification
  - DNS record analysis
  - Homograph attack detection
  - Character substitution detection
  - Brand impersonation checks

- **Fact Verification**:
  - Automated fact extraction
  - Real-time verification against trusted sources
  - Source credibility assessment
  - Confidence scoring

- **Engaging Output**:
  - Character-based analysis presentation
  - Comprehensive evidence evaluation
  - Clear security recommendations
  - Detailed technical explanations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/verifiedx.git
cd verifiedx
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables in `.env`:
```env
OPENAI_API_KEY=your_openai_key
PERPLEXITY_API_KEY=your_perplexity_key
PINECONE_API_KEY=your_pinecone_key
PINECONE_INDEX=your_index_name
MODEL_PATH=path_to_your_model
```

## Usage

### Command Line Interface
```bash
python analyze.py "message to analyze"
```

### Python API
```python
from src.core.detector import Detector
import asyncio

async def analyze_message(text: str):
    detector = Detector()
    result = await detector.analyze(text)
    print(result)

# Run analysis
asyncio.run(analyze_message("message to analyze"))
```

## Testing

Run the test suite:
```bash
pytest -v
```

Run specific test cases:
```bash
pytest tests/test_system.py -k test_mixed_case
```

## Project Structure

```
verifiedx/
├── src/
│   ├── api/           # API endpoints
│   ├── config/        # Configuration files
│   ├── core/          # Core detection logic
│   └── utils/         # Utility functions
├── tests/             # Test suite
├── analyze.py         # CLI entry point
├── requirements.txt   # Dependencies
└── README.md         # Documentation
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OpenAI for the O3-mini model
- Perplexity for fact verification API
- Pinecone for vector similarity search
- HuggingFace for transformer models 