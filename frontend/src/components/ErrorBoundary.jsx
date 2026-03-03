import { Component } from 'react';

/**
 * ErrorBoundary — Catches uncaught React rendering errors
 * and displays a recovery UI instead of a blank screen.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo });
    // In production, send this to your error-tracking service
    console.error('[ErrorBoundary]', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <div className="error-boundary-card">
            <span className="error-icon">⚠️</span>
            <h2>Something went wrong</h2>
            <p className="error-message">
              {this.state.error?.message || 'An unexpected error occurred.'}
            </p>
            {this.state.errorInfo && (
              <details className="error-details">
                <summary>Stack trace</summary>
                <pre>{this.state.errorInfo.componentStack}</pre>
              </details>
            )}
            <button className="btn-primary" onClick={this.handleReset}>
              Try Again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
