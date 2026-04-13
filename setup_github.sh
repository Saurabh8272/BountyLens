#!/bin/bash
# BountyLens — One-command GitHub setup
# Usage: chmod +x setup_github.sh && ./setup_github.sh

echo "🔍 BountyLens — GitHub Setup"
echo "=============================="
echo ""

# Ask for GitHub username
read -p "Enter your GitHub username: " GH_USER

if [ -z "$GH_USER" ]; then
    echo "❌ Username required. Exiting."
    exit 1
fi

REPO_URL="https://github.com/$GH_USER/BountyLens.git"

echo ""
echo "⚠️  Before running this, make sure you've created the repo on GitHub:"
echo "   1. Go to https://github.com/new"
echo "   2. Name: BountyLens"
echo "   3. Public, no README, no .gitignore"
echo "   4. Click 'Create repository'"
echo ""
read -p "Have you created the repo? (y/n): " CONFIRM

if [ "$CONFIRM" != "y" ]; then
    echo "Go create it first, then run this again."
    exit 1
fi

# Initialize and push
git init
git add .
git commit -m "🔍 BountyLens v2.0 — AI-powered API Security Testing Platform

Features:
- Burp Suite extension with auto endpoint capture
- MCP server integration with Claude
- 40+ security test cases (OWASP API Top 10 mapped)
- HackerOne/Bugcrowd/Hacktify bounty patterns
- BOLA/BFLA deep-dive checklists
- Smart auto-selection based on endpoint analysis
- Three views: per-endpoint, per-parameter, per-vulnerability-class
- Toggle tests on/off
- Pass/fail/NA tracking with evidence
- Business context and risk annotations
- Export reports in Word/PDF/JSON"

git branch -M main
git remote add origin $REPO_URL
git push -u origin main

echo ""
echo "✅ Done! Your repo is live at: https://github.com/$GH_USER/BountyLens"
echo ""
