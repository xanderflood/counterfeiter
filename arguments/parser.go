package arguments

import (
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	"github.com/maxbrunsfeld/counterfeiter/terminal"
)

type PathAndOutputOptions struct {
	SourcePackageDir       string // abs path to the dir containing the interface to fake
	ImportPath             string // import path to the package containing the interface to fake
	OutputPath             string // path to write the fake file to
	DestinationPackageName string // often the base-dir for OutputPath but must be a valid package name
}

type PathResolver interface {
	ResolvePath() PathAndOutputOptions
}

func NewPathResolver() PathResolver {
	return pathResolver{}
}

type pathResolver struct{}

func (p pathResolver) ResolvePath() PathAndOutputOptions {
	return PathAndOutputOptions{

	}
}

// ^^^ THERE BE DRAGONS UP THUR ^^^

type ParsedArguments struct {
	SourcePackageDir       string // abs path to the dir containing the interface to fake
	ImportPath             string // import path to the package containing the interface to fake
	OutputPath             string // path to write the fake file to
	DestinationPackageName string // often the base-dir for OutputPath but must be a valid package name

	DestinationDir     string // either the current working directory OR the dir specified as the first argument
	OptionalOutputPath string // if the user specifies an output path with -o, it will be here

	InterfaceName string // the name of the interface to counterfeit
	FakeImplName  string // the name of the struct implementing the given interface
	PrintToStdOut bool   // triggers writing to stdout or to "output path"

	GenerateInterfaceAndShimFromPackageDirectory bool // triggers "package" mode, as opposed to "interface" mode
}

type ArgumentParser interface {
	ParseArguments(...string) ParsedArguments
}

type argumentParser struct {
	ui                terminal.UI
	failHandler       FailHandler
	currentWorkingDir CurrentWorkingDir
	symlinkEvaler     SymlinkEvaler
	fileStatReader    FileStatReader
}

func NewArgumentParser(
	failHandler FailHandler,
	currentWorkingDir CurrentWorkingDir,
	symlinkEvaler SymlinkEvaler,
	fileStatReader FileStatReader,
	ui terminal.UI,
) ArgumentParser {
	return &argumentParser{
		ui:                ui,
		failHandler:       failHandler,
		currentWorkingDir: currentWorkingDir,
		symlinkEvaler:     symlinkEvaler,
		fileStatReader:    fileStatReader,
	}
}

func (argParser *argumentParser) ParseArguments(args ...string) ParsedArguments {
	if *packageFlag {
		return argParser.parsePackageArgs(args...)
	} else {
		return argParser.parseInterfaceArgs(args...)
	}
}

func (argParser *argumentParser) parseInterfaceArgs(args ...string) ParsedArguments {
	var interfaceName string
	var outputPathFlagValue string
	var rootDestinationDir string
	var sourcePackageDir string
	var importPath string

	if outputPathFlag != nil {
		outputPathFlagValue = *outputPathFlag
	}

	if len(args) > 1 {
		interfaceName = args[1]
		sourcePackageDir = argParser.getSourceDir(args[0])
		rootDestinationDir = sourcePackageDir
	} else {
		fullyQualifiedInterface := strings.Split(args[0], ".")
		interfaceName = fullyQualifiedInterface[len(fullyQualifiedInterface)-1]
		rootDestinationDir = argParser.currentWorkingDir()
		importPath = strings.Join(fullyQualifiedInterface[:len(fullyQualifiedInterface)-1], ".")
	}

	fakeImplName := getFakeName(interfaceName, *fakeNameFlag)

	outputPath := argParser.getOutputPath(
		rootDestinationDir,
		fakeImplName,
		outputPathFlagValue,
	)

	packageName := restrictToValidPackageName(filepath.Base(filepath.Dir(outputPath)))

	return ParsedArguments{
		SourcePackageDir:       sourcePackageDir,
		OutputPath:             outputPath,
		ImportPath:             importPath,
		DestinationPackageName: packageName,

		DestinationDir:     argParser.getDestinationDir(rootDestinationDir, outputPathFlagValue),
		OptionalOutputPath: outputPathFlagValue,

		InterfaceName: interfaceName,
		FakeImplName:  fakeImplName,
		PrintToStdOut: any(args, "-"),

		GenerateInterfaceAndShimFromPackageDirectory: false,
	}
}

func (argParser *argumentParser) parsePackageArgs(args ...string) ParsedArguments {
	dir := argParser.getPackageDir(args[0])

	packageName := path.Base(dir) + "shim"

	var outputPath string
	if *outputPathFlag != "" {
		// TODO: sensible checking of dirs and symlinks
		outputPath = *outputPathFlag
	} else {
		outputPath = path.Join(argParser.currentWorkingDir(), packageName)
	}

	return ParsedArguments{
		SourcePackageDir:       dir,
		OutputPath:             outputPath,
		DestinationPackageName: packageName,

		PrintToStdOut: any(args, "-"),

		OptionalOutputPath: *outputPathFlag,

		GenerateInterfaceAndShimFromPackageDirectory: true,
	}
}

func fixupUnexportedNames(interfaceName string) string {
	asRunes := []rune(interfaceName)
	if len(asRunes) == 0 || !unicode.IsLower(asRunes[0]) {
		return interfaceName
	}
	asRunes[0] = unicode.ToUpper(asRunes[0])
	return string(asRunes)
}

func getFakeName(interfaceName, arg string) string {
	if arg == "" {
		interfaceName = fixupUnexportedNames(interfaceName)
		return "Fake" + interfaceName
	} else {
		return arg
	}
}

var camelRegexp = regexp.MustCompile("([a-z])([A-Z])")

func (argParser *argumentParser) getOutputPath(rootDestinationDir, fakeName, arg string) string {
	if arg == "" {
		snakeCaseName := strings.ToLower(camelRegexp.ReplaceAllString(fakeName, "${1}_${2}"))
		return filepath.Join(rootDestinationDir, packageNameForPath(rootDestinationDir), snakeCaseName+".go")
	}

	if !filepath.IsAbs(arg) {
		arg = filepath.Join(argParser.currentWorkingDir(), arg)
	}
	return arg
}

func (argParser *argumentParser) getDestinationDir(rootDestinationDir, possibleOutputPath string) string {
	if possibleOutputPath == "" {
		return filepath.Join(rootDestinationDir, packageNameForPath(rootDestinationDir))
	}

	if !filepath.IsAbs(possibleOutputPath) {
		possibleOutputPath = filepath.Join(argParser.currentWorkingDir(), possibleOutputPath)
	}

	return possibleOutputPath
}

func packageNameForPath(pathToPackage string) string {
	_, packageName := filepath.Split(pathToPackage)
	return packageName + "fakes"
}

func (argParser *argumentParser) getPackageDir(arg string) string {
	if filepath.IsAbs(arg) {
		return arg
	}

	pathToCheck := path.Join(runtime.GOROOT(), "src", arg)

	stat, err := argParser.fileStatReader(pathToCheck)
	if err != nil {
		argParser.failHandler("No such file or directory '%s'", arg)
	}
	if !stat.IsDir() {
		argParser.failHandler("No such file or directory '%s'", arg)
	}

	return pathToCheck
}

func (argParser *argumentParser) getSourceDir(path string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(argParser.currentWorkingDir(), path)
	}

	evaluatedPath, err := argParser.symlinkEvaler(path)
	if err != nil {
		argParser.failHandler("No such file/directory/package: '%s'", path)
	}

	stat, err := argParser.fileStatReader(evaluatedPath)
	if err != nil {
		argParser.failHandler("No such file/directory/package: '%s'", path)
	}

	if !stat.IsDir() {
		return filepath.Dir(path)
	} else {
		return path
	}
}

func any(slice []string, needle string) bool {
	for _, str := range slice {
		if str == needle {
			return true
		}
	}

	return false
}

func restrictToValidPackageName(input string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		} else {
			return -1
		}
	}, input)
}

type FailHandler func(string, ...interface{})
