package arguments

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Determining various paths for a fake", func() {
	var subject PathResolver

	JustBeforeEach(func() {
		subject = NewPathResolver()
	})

	It("resolves the source package dir", func() {

	})

	It("resolves the import path", func() {

	})

	It("resolves the output path", func() {

	})

	It("reoslves the destination package name", func() {

	})
})
