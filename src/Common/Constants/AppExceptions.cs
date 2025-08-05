namespace PlatformApi.Common.Constants;
  
public class NotFoundException : Exception
{

    public NotFoundException() : base(ErrorMessages.NotFound)
    {
    }

    public NotFoundException(string message) : base(message)
    {
    }
}


public class ServiceException : Exception
{
    public ServiceException() : base(ErrorMessages.UnknownError)
    {
    }

    public ServiceException(string message) : base(message)
    {
    }
}