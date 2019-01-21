package handlers

import (
	"github.com/GymWorkoutApp/gwap-auth/errors"
	"github.com/labstack/echo"
	"reflect"
)

func HandleError(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		result := next(c)
		if reflect.TypeOf(result).Name() != "Response" {
			return errors.NewResponse(result, errors.StatusCodes[result], errors.Descriptions[result])
		}
		return result
	}
}