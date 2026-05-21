echo "Starting Capacitor Setup..."

set -e
if [ ! -f package.json ]; then
    echo "Initializing NPM..."
    npm init -y
fi

echo "Installing Dependencies..."
npm install

if [ ! -f capacitor.config.json ]; then
    echo "Initializing Capacitor..."
    npx cap init IsteApp com.iste.app --web-dir www
fi

if [ ! -d android ]; then
    echo "Adding Android platform..."
    npx cap add android
fi

echo "Building web assets..."
if [ ! -d www ]; then
    mkdir -p www
    cp -r ./static/* ./www/
fi

echo "Copying assets to Android..."
npx cap copy

echo "Syncing Capacitor..."
npx cap sync android

echo "Done! Your Capacitor Android project is ready."
echo "Open Android Studio to build the APK manually."
