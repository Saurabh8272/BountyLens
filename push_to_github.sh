#!/bin/bash

# ═══════════════════════════════════════════
# BountyLens — One-Click GitHub Push Script
# ═══════════════════════════════════════════

echo "🔍 BountyLens — GitHub Setup"
echo "═══════════════════════════════"
echo ""

# Ask for GitHub username
read -p "Enter your GitHub username: " GITHUB_USER

if [ -z "$GITHUB_USER" ]; then
    echo "❌ Username cannot be empty."
    exit 1
fi

echo ""
echo "📋 Steps this script will do:"
echo "  1. Initialize git repo"
echo "  2. Add all files"
echo "  3. Commit"
echo "  4. Push to github.com/$GITHUB_USER/BountyLens"
echo ""
echo "⚠️  Make sure you've already created the repo on GitHub:"
echo "    https://github.com/new  →  Name: BountyLens  →  Public  →  No README  →  Create"
echo ""
read -p "Ready? (y/n): " READY

if [ "$READY" != "y" ]; then
    echo "Cancelled."
    exit 0
fi

# Initialize
git init
git add .
git commit -m "feat: BountyLens v2 - AI-powered API Security Testing Platform

- Burp Suite extension (Jython) with auto endpoint capture
- MCP server with Claude integration
- 40+ security test cases (OWASP API Top 10 mapped)
- HackerOne/Bugcrowd/Hacktify bounty report patterns
- BOLA/BFLA deep-dive checklists
- Auto-selection engine based on parameter analysis
- Three views: per-endpoint, per-parameter, per-vulnerability-class
- Toggle test cases on/off
- Smart tracking dashboard (pass/fail/NA/skip)
- Export reports in Word/PDF/JSON
- Custom test case support"

# Push
git branch -M main
git remote add origin "https://github.com/$GITHUB_USER/BountyLens.git"
git push -u origin main

echo ""
echo "✅ Done! Your repo is live at:"
echo "   https://github.com/$GITHUB_USER/BountyLens"
echo ""
