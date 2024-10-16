using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Threading.Tasks;
using System;
using SharedLibrary.Dtos;

namespace UdemyAuthServer.Core.Services
{
    public interface IServiceGeneric<TEntity, TDto> 
        where TEntity : class 
        where TDto : class
    {
        Task<Response<TDto>> GetByIdAsync(int id);
        Task<Response<IEnumerable<TEntity>>> GetAllAsync();
        Task<Response<IEnumerable<TDto>>> Where(Expression<Func<TEntity, bool>> predicate);
        Task<Response<TDto>> AddAsync(TEntity entity);
        Task<Response<NoDataDto>> Remove(TEntity entity);
        Task<Response<NoDataDto>> Update(TEntity entity);
    }
}
