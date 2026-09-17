# Exceptions

The HTTP exceptions CRUDAuth raises. All subclass `CustomException`, which is a FastAPI
`HTTPException`, so they propagate with the right status code and headers.

::: crudauth.exceptions.CustomException

::: crudauth.exceptions.BadRequestException

::: crudauth.exceptions.OAuthAccountException

::: crudauth.exceptions.NotFoundException

::: crudauth.exceptions.ForbiddenException

::: crudauth.exceptions.UnauthorizedException

::: crudauth.exceptions.UnprocessableEntityException

::: crudauth.exceptions.DuplicateValueException

::: crudauth.exceptions.ValueTooLongException

::: crudauth.exceptions.PasswordPolicyException

::: crudauth.exceptions.RateLimitException

::: crudauth.exceptions.SudoLockoutError

::: crudauth.exceptions.CSRFException
