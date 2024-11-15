const firstNames = [
	  "Aaron", "Adam", "Adrian", "Aiden", "Alexander", "Andrew", "Angel", "Anthony", "Asher", "Austin", "Axel",
	  "Beau", "Benjamin", "Bennett", "Brooks", "Caleb", "Cameron", "Carlie", "Carley", "Carson", "Carter", "Charles",
	  "Christian", "Christopher", "Colton", "Connor", "Cooper", "Damian", "Daniel", "David", "Declan", "Dylan",
	  "Easton", "Eli", "Elijah", "Elias", "Elvis", "Emmett", "Ethan", "Everett", "Ezra", "Gabriel", "Grace",
	  "Grayson", "Greyson", "Henry", "Hudson", "Hunter", "Ian", "Isaac", "Isaiah", "Jack", "Jackson", "Jacob",
	  "Jace", "James", "Jameson", "Jayden", "Jeremiah", "John", "Jonathan", "Jordan", "Joseph", "Josiah",
	  "Joshua", "Julian", "Justin", "Kai", "Kayden", "Landon", "Leo", "Leonardo", "Levi", "Liam", "Lincoln",
	  "Logan", "Lucas", "Luke", "Mary", "Mateo", "Matthew", "Maverick", "Michael", "Micah", "Miles", "Nathan",
	  "Nicholas", "Nolan", "Noah", "Owen", "Parker", "Robert", "Roman", "Ryan", "Samuel", "Santiago",
	  "Sebastian", "Silas", "Theodore", "Thomas", "Waylon", "Wesley", "Weston", "William", "Wyatt", "Xavier"
	];
const lastNames = [
	  "Adams", "Alvarez", "Allen", "Anderson", "Bailey", "Baker", "Barnes", "Bell", "Bennett", "Brown",
	  "Butler", "Campbell", "Carter", "Castillo", "Chavez", "Clark", "Coleman", "Collins", "Cook", "Cooper",
	  "Cox", "Cranford", "Cruz", "Davis", "Diaz", "Edwards", "Evans", "Flores", "Foster", "Garcia", "Gomez",
	  "Gonzalez", "Gray", "Green", "Gutierrez", "Hall", "Harris", "Henderson", "Hernandez", "Hill", "Howard",
	  "Hughes", "Jackson", "James", "Jenkins", "Jimenez", "Johnson", "Jones", "Kelly", "Kim", "King",
	  "Lee", "Lewis", "Long", "Lopez", "Martinez", "Martin", "Martinez", "Mendoza", "Miller", "Mitchell",
	  "Moore", "Morales", "Morgan", "Morris", "Murphy", "Myers", "Nelson", "Nguyen", "Ortiz", "Parker",
	  "Patel", "Perez", "Perry", "Peterson", "Phillips", "Powell", "Price", "Ramirez", "Ramos", "Reed",
	  "Reyes", "Richardson", "Rivera", "Roberts", "Robinson", "Rodriguez", "Rogers", "Ross", "Russell", "Ruiz",
	  "Sanchez", "Sanders", "Scott", "Smith", "Stewart", "Sullivan", "Taylor", "Thomas", "Thompson", "Torres",
	  "Turner", "Walker", "Ward", "Watson", "White", "Williams", "Wilson", "Wood", "Wright", "Young"
	];
const credentialNames = [
	  "Access", "Admin", "Alternate", "Authenticator", "Auth", "Authn", "Backup", "Biometric", 
	  "Bluetooth", "Browser", "Cloud", "Code", "Compliance", "Contactless", "CrossPlatform", 
	  "Credential", "Custom", "Device", "DeviceLock", "Digital", "Face", "FIDO", 
	  "Fast", "Fingerprint", "Hardware", "Identity", "Local", "Login", "Main", "Manager", 
	  "Master", "Mobile", "Network", "NFC", "Passkey", "Passwordless", "Personal", "Persistent", 
	  "Physical", "PlatformKey", "Primary", "ProtectedKey", "Recovery", "ResidentKey", 
	  "SecondFactor", "Secure", "SecureCredential", "Secure", "Security", "Service", 
	  "Session", "SingleSignOn", "SmartCard", "SSO", "Temporary", "Temp", "Touch", 
	  "Transient", "Trusted", "TrustedAuthenticator", "USB", "User", "Verification", 
	  "Virtual", "Voice", "Web", "WebAuthnKey", "Work"
	];
const credentialTypes = [
	  "Card", "Certificate", "Credential", "Cryptography", "Device", "Gesture", "Hardware",
	  "Key", "Key Pair", "Keychain", "Lock", "Mechanism", "Module", "Node", "Object", "Passkey",
	  "Protocol", "PublicKey", "Smartcard", "SSO", "Token", "Tool", "Trust", "Wallet"
	];

function randomUsername() {
    return `user${1000000 + Math.floor(Math.random() * 1000000)}`;
}
function randomDisplayName() {
    const firstName = firstNames[Math.floor(Math.random() * firstNames.length)];
    const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];
    return firstName + ' ' + lastName;
}
function randomCredentialNickname() {
    const credentialName = credentialNames[Math.floor(Math.random() * credentialNames.length)];
    const credentialType = credentialTypes[Math.floor(Math.random() * credentialTypes.length)];
    return credentialName + ' ' + credentialType;
}
