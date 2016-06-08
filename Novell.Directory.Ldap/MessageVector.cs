/******************************************************************************
* The MIT License
* Copyright (c) 2003 Novell Inc.  www.novell.com
* 
* Permission is hereby granted, free of charge, to any person obtaining  a copy
* of this software and associated documentation files (the Software), to deal
* in the Software without restriction, including  without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
* copies of the Software, and to  permit persons to whom the Software is 
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in 
* all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*******************************************************************************/
//
// Novell.Directory.Ldap.MessageVector.cs
//
// Author:
//   Sunil Kumar (Sunilk@novell.com)
//
// (C) 2003 Novell, Inc (http://www.novell.com)
//

using System;

namespace Novell.Directory.Ldap
{
    using System.Collections.Generic;
    using System.Linq;

    /// <summary> The <code>MessageVector</code> class implements additional semantics
	/// to Vector needed for handling messages.
	/// </summary>
	/* package */
	class MessageVector<T>:List<T> where T:class
	{
		/// <summary>Returns an array containing all of the elements in this MessageVector.
		/// The elements returned are in the same order in the array as in the
		/// Vector.  The contents of the vector are cleared.
		/// 
		/// </summary>
		/// <returns> the array containing all of the elements.
		/// </returns>
		virtual internal T[] ObjectArray
		{
			get
			{
			    lock (this)
			    {
			        var results = new T[Count];
			        Array.Copy(ToArray(), 0, results, 0, Count);
			        for (var i = 0; i < Count; i++)
			        {
			            ToArray()[i] = default(T);
			        }
			        //Count = 0;
			        return results;
			    }
			}
			
		}
		internal MessageVector(int cap, int incr):base(cap)
		{
			return ;
		}
		
		/// <summary> Finds the Message object with the given MsgID, and returns the Message
		/// object. It finds the object and returns it in an atomic operation.
		/// 
		/// </summary>
		/// <param name="msgId">The msgId of the Message object to return
		/// 
		/// </param>
		/// <returns> The Message object corresponding to this MsgId.
		/// 
		/// @throws NoSuchFieldException when no object with the corresponding
		/// value for the MsgId field can be found.
		/// </returns>
		/* package */
		internal T FindMessageById(int msgId)
		{
		    lock (this)
		    {
                // Temp stuff
		        if (typeof (T) == typeof (Message))
		        {
		            var result = this.OfType<Message>().Single(message => message.MessageID == msgId);
                    return result as T;
                }
		        return default(T);
		    }
		}
	}
}
