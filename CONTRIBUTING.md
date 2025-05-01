# Contributing to CyberKit Pro

Thank you for considering contributing to CyberKit Pro! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

- Check if the bug has already been reported in the Issues section
- Use the bug report template
- Include detailed steps to reproduce the issue
- Include screenshots if applicable
- Specify your operating system and browser

### Suggesting Features

- Check if the feature has already been suggested
- Use the feature request template
- Provide a clear description of the feature
- Explain why this feature would be useful

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests if applicable
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Development Setup

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/cyberkit-pro.git
   cd cyberkit-pro
   ```

2. Set up the backend:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. Set up the frontend:
   ```bash
   cd frontend
   npm install
   ```

4. Start the development servers:
   ```bash
   # In one terminal (backend)
   cd backend
   python app.py
   
   # In another terminal (frontend)
   cd frontend
   npm start
   ```

## Coding Standards

- Follow the existing code style
- Add comments for complex logic
- Write meaningful commit messages
- Keep pull requests focused on a single change

Thank you for your contributions!
