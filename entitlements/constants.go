//go:build darwin

package entitlements

// Well-known App Sandbox entitlement keys.
//
// See Apple's "App Sandbox" documentation for semantics and availability.
const (
	AppSandbox = "com.apple.security.app-sandbox"

	NetworkClient = "com.apple.security.network.client"
	NetworkServer = "com.apple.security.network.server"

	DeviceCamera     = "com.apple.security.device.camera"
	DeviceMicrophone = "com.apple.security.device.microphone"
	DeviceUSB        = "com.apple.security.device.usb"
	DeviceBluetooth  = "com.apple.security.device.bluetooth"
	Print            = "com.apple.security.print"

	AddressBook = "com.apple.security.personal-information.addressbook"
	Location    = "com.apple.security.personal-information.location"
	Calendars   = "com.apple.security.personal-information.calendars"

	FilesUserSelectedReadOnly  = "com.apple.security.files.user-selected.read-only"
	FilesUserSelectedReadWrite = "com.apple.security.files.user-selected.read-write"

	FilesDownloadsReadOnly  = "com.apple.security.files.downloads.read-only"
	FilesDownloadsReadWrite = "com.apple.security.files.downloads.read-write"

	AssetsPicturesReadOnly  = "com.apple.security.assets.pictures.read-only"
	AssetsPicturesReadWrite = "com.apple.security.assets.pictures.read-write"

	AssetsMusicReadOnly  = "com.apple.security.assets.music.read-only"
	AssetsMusicReadWrite = "com.apple.security.assets.music.read-write"

	AssetsMoviesReadOnly  = "com.apple.security.assets.movies.read-only"
	AssetsMoviesReadWrite = "com.apple.security.assets.movies.read-write"

	ApplicationGroups = "com.apple.security.application-groups"

	// Inherit allows an embedded helper tool to inherit the app sandbox.
	Inherit = "com.apple.security.inherit"

	// GetTaskAllow enables debugging but is incompatible with Inherit.
	GetTaskAllow = "com.apple.security.get-task-allow"

	// FilesAll grants unrestricted access to all files. Apple grants it
	// sparingly (it largely defeats the sandbox), but it is a current entitlement,
	// not a deprecated one.
	FilesAll = "com.apple.security.files.all"

	// PrivilegedFileOperations permits creating symbolic links, replacing
	// files, and setting file attributes on behalf of the user.
	PrivilegedFileOperations = "com.apple.developer.security.privileged-file-operations"

	// BookmarksAppScope and BookmarksDocumentScope are required
	// to create and resolve security-scoped bookmarks (see SecurityScopedBookmarkForPath
	// and ResolveSecurityScopedBookmark). App-scoped bookmarks persist a folder the user
	// granted to the app; document-scoped bookmarks are stored alongside a document.
	BookmarksAppScope      = "com.apple.security.files.bookmarks.app-scope"
	BookmarksDocumentScope = "com.apple.security.files.bookmarks.document-scope"

	// NSAppDataUsageDescription is the Info.plist key that explained why an app
	// needed to read other apps' sandbox containers.
	//
	// Deprecated: Apple has deprecated this key. It is an Info.plist string key, not a
	// code-signing entitlement, and is provided only for documentation completeness.
	NSAppDataUsageDescription = "NSAppDataUsageDescription"
)
