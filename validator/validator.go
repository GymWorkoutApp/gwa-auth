package validator

import (
	"github.com/go-playground/locales/en"
	"github.com/go-playground/universal-translator"
	"gopkg.in/go-playground/validator.v9"
	enTranslation "gopkg.in/go-playground/validator.v9/translations/en"
)

var (
	uni      *ut.UniversalTranslator
)

type (
	CustomValidator struct {
		Validator *validator.Validate
	}
)

func NewValidator() *CustomValidator {
	en := en.New()
	uni = ut.New(en, en)

	newValidator := &CustomValidator{Validator: validator.New()}

	trans, _ := uni.GetTranslator("en")

	enTranslation.RegisterDefaultTranslations(newValidator.Validator, trans)

	return newValidator
}

func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.Validator.Struct(i)
}

func TranslateValidator(err error) []string {
	errs := err.(validator.ValidationErrors)
	msgs := make([]string, 0)
	trans, _ := uni.GetTranslator("en")
	for _, e := range errs {
		msgs = append(msgs, e.Translate(trans))
	}
	return msgs
}