#!/bin/bash

# Falcon Quick Update Script
# Simple script to update Falcon using git

echo "🦅 Falcon Quick Update"
echo "======================"

# Check if we're in the right directory
if [ ! -f "main.py" ]; then
    echo "❌ Error: Not in Falcon directory"
    echo "💡 Please run this script from the Falcon directory"
    exit 1
fi

# Check if git is available
if ! command -v git &> /dev/null; then
    echo "❌ Error: Git is not installed"
    echo "💡 Please install Git to use this update script"
    exit 1
fi

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ Error: Not a git repository"
    echo "💡 Clone Falcon using: git clone https://github.com/dharmraj8033/Falcon.git"
    exit 1
fi

echo "🔍 Checking for updates..."

# Fetch latest changes
git fetch origin

# Check if updates are available
COMMITS_BEHIND=$(git rev-list --count HEAD..origin/main)

if [ "$COMMITS_BEHIND" -eq 0 ]; then
    echo "✅ Falcon is already up to date!"
    exit 0
fi

echo "🎉 $COMMITS_BEHIND new commits available!"

# Ask user if they want to update
read -p "🤔 Update now? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "⏭️ Update cancelled"
    exit 0
fi

echo "🚀 Updating Falcon..."

# Pull latest changes
if git pull origin main; then
    echo "✅ Successfully updated Falcon!"
    
    # Update Python dependencies
    echo "📦 Updating dependencies..."
    if python3 -m pip install -r requirements.txt; then
        echo "✅ Dependencies updated!"
    else
        echo "⚠️  Some dependencies may need manual update"
    fi
    
    echo "🎉 Update completed successfully!"
    echo "💡 Restart any running Falcon instances to use the latest version"
else
    echo "❌ Update failed!"
    echo "💡 You may need to resolve conflicts manually"
    exit 1
fi
